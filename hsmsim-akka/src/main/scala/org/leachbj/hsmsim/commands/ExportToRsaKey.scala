/**
 * Copyright (c) 2013 Bernard Leach
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.leachbj.hsmsim.commands

import java.lang.Math
import java.security.{KeyFactory, PublicKey}
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{RSAPrivateCrtKeySpec, RSAPublicKeySpec}

import scala.math.BigInt.int2bigInt
import org.leachbj.hsmsim.crypto.DES
import org.leachbj.hsmsim.crypto.LMK
import org.leachbj.hsmsim.util.HexConverter
import akka.util.ByteString
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

import org.bouncycastle.asn1.{ASN1Integer, ASN1Sequence, DERInteger}


case class ExportToRsaKeyRequest(messageHeader:String, desKey: Array[Byte], rsaPublicKey: Array[Byte], keyType: Int, keySchemeLmk: Byte) extends HsmRequest {
  override def toString() = {
    "ExportToRsaKeyRequest(" + HexConverter.toHex(ByteString(desKey)) + ", " + HexConverter.toHex(ByteString(rsaPublicKey)) + "," + keySchemeLmk + ")"
  }
}
case class ExportToRsaKeyResponse(messageHeader:String, errorCode: String, rsaEncrypted: Array[Byte], keyCheckValue: Array[Byte]) extends HsmResponse {
  val responseCode = "GL"
}
object ExportToRsaKeyResponse {

  private val (zmkKeyType, zpkKeyType) = (1, 2)

  private def ceil(x: Int): Int = {
    (Math.ceil(x / 24d)).asInstanceOf[Int] * 3
  }

  private def createPublicKey(encodedRsaPublicKey: Array[Byte]) = {
    println("public key: " + HexConverter.toHex(ByteString(encodedRsaPublicKey)))
    val sequence = ASN1Sequence.getInstance(encodedRsaPublicKey)
    val modulus = DERInteger.getInstance(sequence.getObjectAt(0)).asInstanceOf[ASN1Integer]
    val exponent = DERInteger.getInstance(sequence.getObjectAt(1)).asInstanceOf[ASN1Integer]
    val keySpec = new RSAPublicKeySpec(modulus.getPositiveValue, exponent.getPositiveValue)
    val factory = KeyFactory.getInstance("RSA")
    factory.generatePublic(keySpec)
  }


  private def encryptKeyUnderRsa(publicKey: PublicKey, data: Array[Byte]) = {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    cipher.doFinal(data);
  }

  def createResponse(req: ExportToRsaKeyRequest): HsmResponse = {

    val lmkKeyType = req.keyType match {
      case `zmkKeyType` =>
        LMK.lmkVariant("04-05", 0)
      case `zpkKeyType` =>
        LMK.lmkVariant("06-07", 0)
    }

    val clearDesKey = DES.tripleDesDecryptVariant(lmkKeyType, req.desKey)
    val publicKey = createPublicKey(req.rsaPublicKey)
    val rsaEncrypted = encryptKeyUnderRsa(publicKey, clearDesKey)
    val keyCheckValue = DES.calculateCheckValue(clearDesKey).take(6)

    println("clearDesKey: " + HexConverter.toHex(ByteString(clearDesKey)))
    println("keyCheckValue: " + HexConverter.toHex(ByteString(keyCheckValue)))
    println("rsaEncrypted: " + HexConverter.toHex(ByteString(rsaEncrypted)))
    println("rsaEncrypted Length: " + rsaEncrypted.length)

    ExportToRsaKeyResponse(req.messageHeader, "00", rsaEncrypted, keyCheckValue)
  }
}
