﻿// Copyright (C) 2017-2020 Ixian OU
// This file is part of Ixian Core - www.github.com/ProjectIxian/Ixian-Core
//
// Ixian Core is free software: you can redistribute it and/or modify
// it under the terms of the MIT License as published
// by the Open Source Initiative.
//
// Ixian Core is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// MIT License for more details.

using System.Diagnostics;

namespace IXICore
{
    /// <summary>
    ///  Represents the raw data of an Ixian RSA key value.
    /// </summary>
    /// <remarks>
    ///  The Key Pair includes the RSA public and private keys, serialized from an internal format to make them easier to use in network communications.
    ///  In addition, the `IxianKeyPair` structure also includes the 'nonce' value, which is used to easily and quickly generate new Ixian addresses without having
    ///  to recompute new RSA keys.
    /// </remarks>
    public class IxianKeyPair
    {
        /// <summary>
        /// Serialized format of the RSA public key.
        /// </summary>
        public byte[] publicKeyBytes = null;
        /// <summary>
        /// Serialize format of the RSA private key.
        /// </summary>
        public byte[] privateKeyBytes = null;
        /// <summary>
        /// Most recently used 'nonce' value for generating additional addresses.
        /// </summary>
        public byte[] lastNonceBytes = null; // nonce for generating new addresses
        /// <summary>
        /// Base address for the public key in `publicKeyBytes`.
        /// </summary>
        public byte[] addressBytes = null;
    }

    /// <summary>
    /// Interface for implementing different cryptographic libraries.
    /// </summary>
    public interface ICryptoLib
    {
        /// <summary>
        ///  Generates a new pair of RSA private and public keys.
        /// </summary>
        /// <remarks>
        ///  The serialized key format has changed slightly and the parameter `skip_header` is used to denote older Ixian keys
        ///  which did not include version information. It is recommended that the parameter is left on its default value `false` when
        ///  using this function, unless you have a very specific need togenerate older Ixian keys.
        /// </remarks>
        /// <param name="keySize">Size of the new RSA key, in bits.</param>
        /// <param name="skip_header">Legacy parameter to allow generating older Ixian keys.</param>
        /// <returns>A new RSA key pair and associated Ixian data.</returns>
        IxianKeyPair generateKeys(int keySize, bool skip_header = false);

        /// <summary>
        ///  Generates a cryptographic signature for the input data, using the provided private key in the Ixian serialized format.
        ///  See the class `IxianKeyPair` and the function `generateKeys()` for information about how to obtain a serialized RSA key.
        /// </summary>
        /// <param name="input">Data which should be signed.</param>
        /// <param name="privateKey">Private key for signing the data in Ixian serialized format.</param>
        /// <returns>Signature of the given data with the given key in a byte-field format.</returns>
        byte[] getSignature(byte[] input, byte[] privateKey);
        /// <summary>
        ///  Verifies that the given signature correctly signs the data with the given public key.
        ///  See the class `IxianKeyPair` and the function `generateKeys()` for information about how to obtain a serialized RSA key.
        ///  The signature should be one which has been calculated with the `getSignature()` function.
        /// </summary>
        /// <param name="input">Data which has been signed using the public key's corresponding private key.</param>
        /// <param name="publicKey">Public key against which the signature should be tested.</param>
        /// <param name="signature">Signature, as given by `getSignature()`.</param>
        /// <returns>True, if the signature matches the data and has been generated from the correct private RSA key.</returns>
        bool verifySignature(byte[] input, byte[] publicKey, byte[] signature);

        /// <summary>
        ///  Encrypts the data using RSA cryptography and using the provided public key in the Ixian serialized format.
        ///  See the class `IxianKeyPair` and the function `generateKeys()` for information about how to obtain a serialized RSA key.
        /// </summary>
        /// <param name="input">Cleartext data to encrypt.</param>
        /// <param name="publicKey">RSA public key in the Ixian serialized format.</param>
        /// <returns>Encrypted data (Ciphertext), using RSA cryptography.</returns>
        byte[] encryptWithRSA(byte[] input, byte[] publicKey);
        /// <summary>
        ///  Decrypts the data using RSA cryptography and using the provided private key in the Ixian serialized format.
        ///  See the class `IxianKeyPair` and the function `generateKeys()` for information about how to obtain a serialized RSA key.
        ///  The encrypted data should be the value returned from `encryptWithRSA()` function.
        /// </summary>
        /// <param name="input">Ciphertext data to decrypt.</param>
        /// <param name="privateKey">RSA private key in the Ixian serialized format.</param>
        /// <returns>Decrypted data (Cleartext), using RSA cryptography.</returns>
        byte[] decryptWithRSA(byte[] input, byte[] privateKey);

        /// <summary>
        ///  Encrpyts the provided data with a variant of the AES algorithm and using the provided symmetrical encryption key.
        /// </summary>
        /// <remarks>
        ///  For best results, the key should be as random as possible. The function also generates a random salt value to increase the security of
        ///  encryption. Because the salt value is needed for decryption, it is returned together with the ciphertext.
        ///  The exact algorithm used for encryption is "AES/CBC/PKCS7Padding"
        /// </remarks>
        /// <param name="input">Cleartext data.</param>
        /// <param name="key">Encryption key.</param>
        /// <param name="use_GCM">Uses GCM mode.</param>
        /// <returns>AES-Encrypted data (Ciphertext) and the random salt value used in encryption.</returns>
        byte[] encryptWithAES(byte[] input, byte[] key, bool use_GCM);
        /// <summary>
        ///  Decrypts the provided block of data with a variant of the AES algorithm and using the provided symmetrical encryption key.
        /// </summary>
        /// <remarks>
        ///  This function mirrors `encryptDataAES()`, so the input data should also contain the random salt value used in encryption.
        ///  The function allows processing encrypted data from a larger byte buffer by specifying the offset at which the data starts.
        ///  For most use cases, `offset` should be set to 0.
        /// </remarks>
        /// <param name="input">Ciphertext data to decrypt</param>
        /// <param name="key">Decryption key.</param>
        /// <param name="use_GCM">Uses GCM mode.</param>
        /// <param name="offset">Offset of the encrypted data in the byte-field. This is usually 0.</param>
        /// <returns></returns>
        byte[] decryptWithAES(byte[] input, byte[] key, bool use_GCM, int offset = 0);

        /// <summary>
        ///  Encrypts the provided data with the given password. This function uses `encryptWithAES()` as the internal encryption primitive, but
        ///  abstracts away some of the detail around key and salt generation.
        /// </summary>
        /// <remarks>
        ///  In order to obtain a good encryption key from the password, PBKDF2 from RFC 2898 is used. Since the function also generates a random encryption salt,
        ///  the returned byte-field also includes this salt value.
        /// </remarks>
        /// <param name="data">Cleartext data.</param>
        /// <param name="password">Encryption password.</param>
        /// <param name="use_GCM">Uses GCM mode.</param>
        /// <returns>Ciphertext data with a random salt value.</returns>
        byte[] encryptWithPassword(byte[] data, string password, bool use_GCM);
        /// <summary>
        ///  Encrypts the provided data with the given password. This function uses `decryptWithAES()` as the internal encryption primitive, but
        ///  abstracts away some of the detail around key and salt processing.
        /// </summary>
        /// <remarks>
        ///  In order to obtain a good encryption key from the password, PBKDF2 from RFC 2898 is used. This function is the inverse of `encryptWithPassword()`, so
        ///  it can only process Ciphertext generated by that function.
        /// </remarks>
        /// <param name="data">Ciphertext data.</param>
        /// <param name="password">Encryption password.</param>
        /// <param name="use_GCM">Uses GCM mode.</param>
        /// <returns>Cleartext data.</returns>
        byte[] decryptWithPassword(byte[] data, string password, bool use_GCM);

        /// <summary>
        ///  Encrypts the provided data with the given password. This function uses Bouncy Castle's 'ChaCha' method as the internal encryption primitive, but
        ///  abstracts away some of the detail around key processing.
        /// </summary>
        /// <param name="input">Cleartext data.</param>
        /// <param name="key">Encryption password.</param>
        /// <returns>Ciphertext data.</returns>
        byte[] encryptWithChacha(byte[] input, byte[] key);

        /// <summary>
        ///  Decrypts the provided data with the given password. This function uses Bouncy Castle's 'ChaCha' method as the internal encryption primitive, but
        ///  abstracts away some of the detail around key processing.
        /// </summary>
        /// <param name="input">Ciphertext data.</param>
        /// <param name="key">Decryption password.</param>
        /// <returns>Cleartext data.</returns>
        byte[] decryptWithChacha(byte[] input, byte[] key);

        /// <summary>
        ///  Generates a child RSA key from the given parent RSA key, so that the process may be repeated in the future. This function
        ///  allows for RSA key derivation and hirearchical keys.
        ///  Using a different `seed` value will yield different child keys, but the process can be repeated if the seed values are known.
        /// </summary>
        /// <param name="parentKey">RSA private key in Ixian serialized format.</param>
        /// <param name="seed">A unique seed value.</param>
        /// <returns>A new RSA key in Ixian serialized format.</returns>
        byte[] generateChildKey(byte[] parentKey, int seed = 0);

        /// <summary>
        ///  Verifies that the provided Ixian key pair are valid, working RSA keys. Both encryption and signing are tested and the 
        ///  resulting values are then decrypted and verified to ensure that the process is reversible.
        /// </summary>
        /// <param name="sample">Sample data, used for testing the keys (Cleartext).</param>
        /// <param name="kp">Ixian RSA key pair to be tested.</param>
        /// <returns>True, if the keys are able to successfully encrypt and sign data.</returns>
        bool testKeys(byte[] sample, IxianKeyPair kp);

        /// <summary>
        /// Generates secure random bytes according to the specified length.
        /// </summary>
        /// <param name="length">Length of the random data.</param>
        /// <returns>Byte array of cryptographically secure random data.</returns>
        byte[] getSecureRandomBytes(int length);
    }


    public class CryptoLib
    {
        private ICryptoLib _cryptoLib = null;

        public CryptoLib(ICryptoLib crypto_lib)
        {
            _cryptoLib = crypto_lib;
        }

        public IxianKeyPair generateKeys(int keySize, bool skip_header = false)
        {
            Trace.Assert(_cryptoLib != null);
            return _cryptoLib.generateKeys(keySize, skip_header);
        }

        public byte[] getSignature(byte[] input, byte[] privateKey)
        {
            return _cryptoLib.getSignature(input, privateKey);
        }

        public bool verifySignature(byte[] input, byte[] publicKey, byte[] signature)
        {
            return _cryptoLib.verifySignature(input, publicKey, signature);
        }

        public byte[] encryptWithRSA(byte[] input, byte[] publicKey)
        {
            return _cryptoLib.encryptWithRSA(input, publicKey);
        }

        public byte[] decryptWithRSA(byte[] input, byte[] privateKey)
        {
            return _cryptoLib.decryptWithRSA(input, privateKey);
        }

        public byte[] encryptWithAES(byte[] input, byte[] key, bool use_GCM)
        {
            return _cryptoLib.encryptWithAES(input, key, use_GCM);
        }

        public byte[] decryptWithAES(byte[] input, byte[] key, bool use_GCM, int offset = 0)
        {
            return _cryptoLib.decryptWithAES(input, key, use_GCM, offset);
        }

        public byte[] encryptWithPassword(byte[] data, string password, bool use_GCM)
        {
            return _cryptoLib.encryptWithPassword(data, password, use_GCM);
        }

        public byte[] decryptWithPassword(byte[] data, string password, bool use_GCM)
        {
            return _cryptoLib.decryptWithPassword(data, password, use_GCM);
        }

        public byte[] encryptWithChacha(byte[] input, byte[] key)
        {
            return _cryptoLib.encryptWithChacha(input, key);
        }

        public byte[] decryptWithChacha(byte[] input, byte[] key)
        {
            return _cryptoLib.decryptWithChacha(input, key);
        }

        public byte[] generateChildKey(byte[] parentKey, int seed = 0)
        {
            return _cryptoLib.generateChildKey(parentKey, seed);
        }

        public bool testKeys(byte[] plaintext, IxianKeyPair kp)
        {
            return _cryptoLib.testKeys(plaintext, kp);
        }

        public byte[] getSecureRandomBytes(int length)
        {
            return _cryptoLib.getSecureRandomBytes(length);
        }
    }
}
