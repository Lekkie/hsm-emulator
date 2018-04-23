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

import org.leachbj.hsmsim.crypto.LMK
import org.leachbj.hsmsim.crypto.DES
import org.leachbj.hsmsim.util.HexConverter
import akka.util.ByteString
import java.security.SecureRandom

case class GenerateDekRequest(messageHeader:String, isAtallaVariant: Boolean, mode: Byte, keyType: Byte, scheme: Byte) extends HsmRequest

case class GenerateDekResponse(messageHeader:String, errorCode: String, dekLmk: Array[Byte], checkValue: Array[Byte]) extends HsmResponse {
  val responseCode = "A1"
}

object GenerateDekResponse {
  def createResponse(req: GenerateDekRequest): HsmResponse = {
    val dek = generateDek
    val dekUnderLmk = DES.tripleDesEncryptVariant(LMK.lmkVariant("32-33", 0), dek)
    val checkValue = DES.calculateCheckValue(dek).take(3)
    GenerateDekResponse(req.messageHeader, "00", dekUnderLmk, checkValue)
  }

  private def generateDek = {
    val dek = new Array[Byte](16)
    generator.nextBytes(dek)
    DES.adjustParity(dek)
  }

  private val generator = new SecureRandom
}