{-# LANGUAGE ForeignFunctionInterface #-}

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

module Network.Protocol.TLS.GNU.Foreign where

import           Foreign
import           Foreign.C

-- Type aliases {{{

newtype ReturnCode = ReturnCode { unRC :: CInt }
	deriving (Show, Eq)

newtype CipherAlgorithm = CipherAlgorithm CInt
	deriving (Show, Eq)

newtype KXAlgorithm = KXAlgorithm CInt
	deriving (Show, Eq)

newtype ParamsType = ParamsType CInt
	deriving (Show, Eq)

newtype CredentialsType = CredentialsType CInt
	deriving (Show, Eq)

newtype MACAlgorithm = MACAlgorithm CInt
	deriving (Show, Eq)

newtype DigestAlgorithm = DigestAlgorithm CInt
	deriving (Show, Eq)

newtype CompressionMethod = CompressionMethod CInt
	deriving (Show, Eq)

newtype ConnectionEnd = ConnectionEnd CInt
	deriving (Show, Eq)

newtype AlertLevel = AlertLevel CInt
	deriving (Show, Eq)

newtype AlertDescription = AlertDescription CInt
	deriving (Show, Eq)

newtype HandshakeDescription = HandshakeDescription CInt
	deriving (Show, Eq)

newtype CertificateStatus = CertificateStatus CInt
	deriving (Show, Eq)

newtype CertificateRequest = CertificateRequest CInt
	deriving (Show, Eq)

newtype OpenPGPCrtStatus = OpenPGPCrtStatus CInt
	deriving (Show, Eq)

newtype CloseRequest = CloseRequest CInt
	deriving (Show, Eq)

newtype Protocol = Protocol CInt
	deriving (Show, Eq)

newtype CertificateType = CertificateType CInt
	deriving (Show, Eq)

newtype X509CrtFormat = X509CrtFormat CInt
	deriving (Show, Eq)

newtype CertificatePrintFormats = CertificatePrintFormats CInt
	deriving (Show, Eq)

newtype PKAlgorithm = PKAlgorithm CInt
	deriving (Show, Eq)

newtype SignAlgorithm = SignAlgorithm CInt
	deriving (Show, Eq)

newtype Credentials = Credentials (Ptr Credentials)
newtype Transport = Transport (Ptr Transport)
newtype Session = Session (Ptr Session)
newtype DHParams = DHParams (Ptr DHParams)
newtype RSAParams = RSAParams (Ptr RSAParams)
newtype Priority = Priority (Ptr Priority)

newtype Datum = Datum (Ptr Word8, CUInt)

-- }}}

-- Global library info / state {{{

foreign import ccall safe "gnutls_check_version"
	gnutls_check_version :: CString -> IO CString

foreign import ccall safe "gnutls_extra_check_version"
	gnutls_extra_check_version :: CString -> IO CString

foreign import ccall safe "gnutls_global_init"
	gnutls_global_init :: IO ReturnCode

foreign import ccall safe "gnutls_global_init_extra"
	gnutls_global_init_extra :: IO ReturnCode

foreign import ccall safe "gnutls_global_deinit"
	gnutls_global_deinit :: IO ()

foreign import ccall safe "gnutls_global_set_log_function"
	gnutls_global_set_log_function :: FunPtr (CInt -> CString -> IO ()) -> IO ()

foreign import ccall safe "gnutls_global_set_log_level"
	gnutls_global_set_log_level :: CInt -> IO ()

-- }}}

-- Error handling {{{

foreign import ccall safe "gnutls_error_is_fatal"
	gnutls_error_is_fatal :: ReturnCode -> IO CInt

foreign import ccall safe "gnutls_perror"
	gnutls_perror :: ReturnCode -> IO ()

foreign import ccall safe "gnutls_strerror"
	gnutls_strerror :: ReturnCode -> IO CString

foreign import ccall safe "gnutls_strerror_name"
	gnutls_strerror_name :: ReturnCode -> IO CString

-- }}}

-- Sessions {{{

foreign import ccall safe "gnutls_init"
	gnutls_init :: Ptr (Ptr Session) -> ConnectionEnd -> IO ReturnCode

foreign import ccall safe "gnutls_deinit"
	gnutls_deinit :: Session -> IO ()

foreign import ccall safe "gnutls_handshake"
	gnutls_handshake :: Session -> IO ReturnCode

foreign import ccall safe "gnutls_rehandshake"
	gnutls_rehandshake :: Session -> IO ReturnCode

foreign import ccall safe "gnutls_bye"
	gnutls_bye :: Session -> CloseRequest -> IO ReturnCode

foreign import ccall safe "gnutls_set_default_priority"
	gnutls_set_default_priority :: Session -> IO ReturnCode

-- }}}

-- Alerts {{{

foreign import ccall safe "gnutls_alert_get_name"
	gnutls_alert_get_name :: AlertDescription -> IO CString

foreign import ccall safe "gnutls_error_to_alert"
	gnutls_error_to_alert :: ReturnCode -> Ptr AlertLevel -> IO AlertDescription

foreign import ccall safe "gnutls_alert_get"
	gnutls_alert_get :: Session -> IO AlertDescription

foreign import ccall safe "gnutls_alert_send_appropriate"
	gnutls_alert_send_appropriate :: Session -> ReturnCode -> IO ReturnCode

foreign import ccall safe "gnutls_alert_send"
	gnutls_alert_send :: Session -> AlertLevel -> AlertDescription -> IO ReturnCode

-- }}}

-- Certificates {{{

foreign import ccall safe "gnutls_certificate_allocate_credentials"
	gnutls_certificate_allocate_credentials :: Ptr (Ptr Credentials) -> IO ReturnCode

foreign import ccall safe "&gnutls_certificate_free_credentials"
	gnutls_certificate_free_credentials_funptr :: FunPtr (Ptr Credentials -> IO ())

foreign import ccall safe "gnutls_certificate_type_get_id"
	gnutls_certificate_type_get_id :: CString -> IO CertificateType

foreign import ccall safe "gnutls_certificate_type_get_name"
	gnutls_certificate_type_get_name :: CertificateType -> IO CString

foreign import ccall safe "gnutls_certificate_type_get"
	gnutls_certificate_type_get :: Session -> IO CertificateType

foreign import ccall safe "gnutls_certificate_type_list"
	gnutls_certificate_type_list :: IO (Ptr CertificateType)

foreign import ccall safe "gnutls_certificate_type_set_priority"
	gnutls_certificate_type_set_priority :: Session -> Ptr CInt -> IO ReturnCode

-- }}}

-- Credentials {{{

foreign import ccall safe "gnutls_credentials_clear"
	gnutls_credentials_clear :: Session -> IO ()

foreign import ccall safe "gnutls_credentials_set"
	gnutls_credentials_set :: Session -> CredentialsType -> Ptr a -> IO ReturnCode

-- }}}

-- Records {{{

foreign import ccall safe "gnutls_record_check_pending"
	gnutls_record_check_pending :: Session -> IO CSize

foreign import ccall safe "gnutls_record_disable_padding"
	gnutls_record_disable_padding :: Session -> IO ()

foreign import ccall safe "gnutls_record_get_direction"
	gnutls_record_get_direction :: Session -> IO CInt

foreign import ccall safe "gnutls_record_get_max_size"
	gnutls_record_get_max_size :: Session -> IO CSize

foreign import ccall safe "gnutls_record_recv"
	gnutls_record_recv :: Session -> Ptr a -> CSize -> IO CSize

foreign import ccall safe "gnutls_record_send"
	gnutls_record_send :: Session -> Ptr a -> CSize -> IO CSize

foreign import ccall safe "gnutls_record_set_max_size"
	gnutls_record_set_max_size :: Session -> CSize -> IO CSize

-- }}}

-- Transports {{{

type TransportFunc = Transport -> Ptr () -> CSize -> IO CSize

foreign import ccall safe "gnutls_transport_set_push_function"
	gnutls_transport_set_push_function :: Session -> FunPtr TransportFunc -> IO ()

foreign import ccall safe "gnutls_transport_set_pull_function"
	gnutls_transport_set_pull_function :: Session -> FunPtr TransportFunc -> IO ()

foreign import ccall "wrapper"
	wrapTransportFunc :: TransportFunc -> IO (FunPtr TransportFunc)

-- }}}

-- Utility {{{

foreign import ccall safe "gnutls_global_set_mem_functions"
	gnutls_global_set_mem_functions
		:: FunPtr (CSize -> IO (Ptr ()))
		-> FunPtr (CSize -> CSize -> IO (Ptr ()))
		-> FunPtr (Ptr () -> IO CInt)
		-> FunPtr (Ptr () -> CSize -> IO (Ptr ()))
		-> FunPtr (Ptr () -> IO ())
		-> IO ()

foreign import ccall safe "gnutls_malloc"
	gnutls_malloc :: CSize -> IO (Ptr a)

foreign import ccall safe "gnutls_free"
	gnutls_free :: Ptr a -> IO ()

foreign import ccall safe "gnutls_hex2bin"
	gnutls_hex2bin :: CString -> CSize -> Ptr Word8 -> Ptr CSize -> IO ReturnCode

foreign import ccall safe "gnutls_hex_decode"
	gnutls_hex_decode :: Ptr Datum -> Ptr Word8 -> Ptr CSize -> IO ReturnCode

foreign import ccall safe "gnutls_hex_encode"
	gnutls_hex_encode :: Ptr Datum -> CString -> Ptr CSize -> IO ReturnCode

-- }}}
