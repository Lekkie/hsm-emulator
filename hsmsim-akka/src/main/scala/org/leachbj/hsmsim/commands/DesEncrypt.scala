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

import org.leachbj.hsmsim.crypto.DES
import org.leachbj.hsmsim.crypto.LMK
import org.leachbj.hsmsim.util.HexConverter

import akka.util.ByteString

case class DesEncryptRequest(messageHeader:String, blockNumber: Int, keyType: Int, desKey: Array[Byte], iv: Option[Array[Byte]], message: Array[Byte]) extends HsmRequest
case class DesEncryptResponse(messageHeader:String, errorCode: String, encryptedMessage: Array[Byte]) extends HsmResponse {
  val responseCode = "M1"
}

object DesEncryptResponse {

  private val (zekKeyType, dekKeyType) = (1, 2)


  def createResponse(req: DesEncryptRequest): HsmResponse = {


    val clearDesKey = req.keyType match {
      case `dekKeyType` =>
        DES.tripleDesDecryptVariant(LMK.lmkVariant("32-33", 0), req.desKey)
      case `zekKeyType` =>
        DES.tripleDesDecryptVariant(LMK.lmkVariant("30-31", 0), req.desKey)
    }


    def encrypt(messageByte: Array[Byte]) = {

      println("Clear key: " +  HexConverter.toHex(ByteString(clearDesKey)))
      println("CipherTest: " +  HexConverter.toHex(ByteString(messageByte)))
      val cryptogram = DES.tripleDesEncrypt(clearDesKey, messageByte)
      println("Cryptogram: " + HexConverter.toHex(ByteString(cryptogram)))

      cryptogram
    }

    val encryptedMessage = encrypt(req.message)
    DesEncryptResponse(req.messageHeader, "00", encryptedMessage)
  }
}
