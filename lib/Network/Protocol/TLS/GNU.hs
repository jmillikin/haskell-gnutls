{-# LANGUAGE TypeFamilies #-}

-- Copyright (C) 2010 John Millikin <jmillikin@gmail.com>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

module Network.Protocol.TLS.GNU
	( TLS
	, Session
	, Error (..)
	
	, runTLS
	, runClient
	, getSession
	, handshake
	, rehandshake
	, putBytes
	, getBytes
	, checkPending
	
	-- * Settings
	, Transport (..)
	, handleTransport
	
	, Credentials
	, setCredentials
	, certificateCredentials
	) where

import           Control.Applicative (Applicative, pure, (<*>))
import qualified Control.Concurrent.MVar as M
import           Control.Monad (ap, when, foldM, foldM_)
import qualified Control.Monad.Error as E
import           Control.Monad.Error (ErrorType)
import qualified Control.Monad.Reader as R
import           Control.Monad.Trans (MonadIO, liftIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as B
import           Data.IORef
import qualified Foreign as F
import qualified Foreign.C as F
import           Foreign.Concurrent as FC
import qualified System.IO as IO
import           System.IO.Unsafe (unsafePerformIO)

import           Network.Protocol.TLS.GNU.ErrorT
import qualified Network.Protocol.TLS.GNU.Foreign as F

data Error = Error Integer
	deriving (Show)

globalInitMVar :: M.MVar ()
{-# NOINLINE globalInitMVar #-}
globalInitMVar = unsafePerformIO $ M.newMVar ()

globalInit :: ErrorT Error IO ()
globalInit = do
	let init_ = M.withMVar globalInitMVar $ \_ -> F.gnutls_global_init
	F.ReturnCode rc <- liftIO init_
	when (rc < 0) $ E.throwError $ mapError rc

globalDeinit :: IO ()
globalDeinit = M.withMVar globalInitMVar $ \_ -> F.gnutls_global_deinit

data Session = Session
	{ sessionPtr :: F.ForeignPtr F.Session
	
	-- TLS credentials are not copied into the gnutls session struct,
	-- so pointers to them must be kept alive until the credentials
	-- are no longer needed.
	--
	-- TODO: Have some way to mark credentials as no longer needed.
	--       The current code just keeps them alive for the duration
	--       of the session, which may be excessive.
	, sessionCredentials :: IORef [F.ForeignPtr F.Credentials]
	}

newtype TLS a = TLS { unTLS :: ErrorT Error (R.ReaderT Session IO) a }

instance Functor TLS where
	fmap f = TLS . fmap f . unTLS

instance Applicative TLS where
	pure = TLS . return
	(<*>) = ap

instance Monad TLS where
	return = TLS . return
	m >>= f = TLS $ unTLS m >>= unTLS . f

instance MonadIO TLS where
	liftIO = TLS . liftIO

instance E.MonadError TLS where
	type ErrorType TLS = Error
	throwError = TLS . E.throwError
	catchError m h = TLS $ E.catchError (unTLS m) (unTLS . h)

runTLS :: Session -> TLS a -> IO (Either Error a)
runTLS s tls = R.runReaderT (runErrorT (unTLS tls)) s

runClient :: Transport -> TLS a -> IO (Either Error a)
runClient transport tls = do
	eitherSession <- newSession transport (F.ConnectionEnd 2)
	case eitherSession of
		Left err -> return (Left err)
		Right session -> runTLS session tls

newSession :: Transport -> F.ConnectionEnd -> IO (Either Error Session)
newSession transport end = F.alloca $ \sPtr -> runErrorT $ do
	globalInit
	F.ReturnCode rc <- liftIO $ F.gnutls_init sPtr end
	when (rc < 0) $ E.throwError $ mapError rc
	liftIO $ do
		ptr <- F.peek sPtr
		let session = F.Session ptr
		push <- F.wrapTransportFunc (pushImpl transport)
		pull <- F.wrapTransportFunc (pullImpl transport)
		F.gnutls_transport_set_push_function session push
		F.gnutls_transport_set_pull_function session pull
		_ <- F.gnutls_set_default_priority session
		creds <- newIORef []
		fp <- FC.newForeignPtr ptr $ do
			F.gnutls_deinit session
			globalDeinit
			F.freeHaskellFunPtr push
			F.freeHaskellFunPtr pull
		return (Session fp creds)

getSession :: TLS Session
getSession = TLS R.ask

handshake :: TLS ()
handshake = withSession F.gnutls_handshake >>= checkRC

rehandshake :: TLS ()
rehandshake = withSession F.gnutls_rehandshake >>= checkRC

putBytes :: BL.ByteString -> TLS ()
putBytes = putChunks . BL.toChunks where
	putChunks chunks = do
		maybeErr <- withSession $ \s -> foldM (putChunk s) Nothing chunks
		case maybeErr of
			Nothing -> return ()
			Just err -> E.throwError $ mapError $ fromIntegral err
	
	putChunk s Nothing chunk = B.unsafeUseAsCStringLen chunk $ uncurry loop where
		loop ptr len = do
			let len' = fromIntegral len
			sent <- F.gnutls_record_send s ptr len'
			let sent' = fromIntegral sent
			case len - sent' of
				0 -> return Nothing
				x | x > 0     -> loop (F.plusPtr ptr sent') x
				  | otherwise -> return $ Just x
	
	putChunk _ err _ = return err

getBytes :: Integer -> TLS BL.ByteString
getBytes count = do
	(mbytes, len) <- withSession $ \s ->
		F.allocaBytes (fromInteger count) $ \ptr -> do
		len <- F.gnutls_record_recv s ptr (fromInteger count)
		bytes <- if len >= 0
			then do
				chunk <- B.packCStringLen (ptr, fromIntegral len)
				return $ Just $ BL.fromChunks [chunk]
			else return Nothing
		return (bytes, len)
	
	case mbytes of
		Just bytes -> return bytes
		Nothing   -> E.throwError $ mapError $ fromIntegral len

checkPending :: TLS Integer
checkPending = withSession $ \s -> do
	pending <- F.gnutls_record_check_pending s
	return $ toInteger pending

data Transport = Transport
	{ transportPush :: BL.ByteString -> IO ()
	, transportPull :: Integer -> IO BL.ByteString
	}

pullImpl :: Transport -> F.TransportFunc
pullImpl t _ buf bufSize = do
	bytes <- transportPull t $ toInteger bufSize
	let loop ptr chunk =
		B.unsafeUseAsCStringLen chunk $ \(cstr, len) -> do
		F.copyArray (F.castPtr ptr) cstr len
		return $ F.plusPtr ptr len
	foldM_ loop buf $ BL.toChunks bytes
	return $ fromIntegral $ BL.length bytes

pushImpl :: Transport -> F.TransportFunc
pushImpl t _ buf bufSize = do
	let buf' = F.castPtr buf
	bytes <- B.unsafePackCStringLen (buf', fromIntegral bufSize)
	transportPush t $ BL.fromChunks [bytes]
	return bufSize

handleTransport :: IO.Handle -> Transport
handleTransport h = Transport (BL.hPut h) (BL.hGet h . fromInteger)

data Credentials = Credentials F.CredentialsType (F.ForeignPtr F.Credentials)

setCredentials :: Credentials -> TLS ()
setCredentials (Credentials ctype fp) = do
	rc <- withSession $ \s ->
		F.withForeignPtr fp $ \ptr -> do
		F.gnutls_credentials_set s ctype ptr
	
	s <- getSession
	if F.unRC rc == 0
		then liftIO (atomicModifyIORef (sessionCredentials s) (\creds -> (fp:creds, ())))
		else checkRC rc

certificateCredentials :: TLS Credentials
certificateCredentials = do
	(rc, ptr) <- liftIO $ F.alloca $ \ptr -> do
		rc <- F.gnutls_certificate_allocate_credentials ptr
		ptr' <- if F.unRC rc < 0
			then return F.nullPtr
			else F.peek ptr
		return (rc, ptr')
	checkRC rc
	fp <- liftIO $ F.newForeignPtr F.gnutls_certificate_free_credentials_funptr ptr
	return $ Credentials (F.CredentialsType 1) fp

withSession :: (F.Session -> IO a) -> TLS a
withSession io = do
	s <- getSession
	liftIO $ F.withForeignPtr (sessionPtr s) $ io . F.Session

checkRC :: F.ReturnCode -> TLS ()
checkRC (F.ReturnCode x) = when (x < 0) $ E.throwError $ mapError x

mapError :: F.CInt -> Error
mapError = Error . toInteger
