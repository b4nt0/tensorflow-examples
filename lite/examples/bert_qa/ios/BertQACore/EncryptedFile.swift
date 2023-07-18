import Foundation
import CommonCrypto

extension Data {
    init?(fromHexEncodedString hexString: String) {
        let cleanedString = hexString.replacingOccurrences(of: " ", with: "")
        var data = Data(capacity: cleanedString.count / 2)

        var index = cleanedString.startIndex
        while index < cleanedString.endIndex {
            let byteString = cleanedString[index ..< cleanedString.index(index, offsetBy: 2)]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            } else {
                return nil // Invalid hex string
            }
            index = cleanedString.index(index, offsetBy: 2)
        }

        self = data
    }
}

func decryptFile(fileName: String, keyHex: String) -> String? {
    guard let url = URL(string: fileName) else { return nil }
    let justFileName = url.lastPathComponent
    guard let filePath = Bundle.main.path(forResource: justFileName, ofType: nil) else {
        print("File not found in the main bundle")
        return nil
    }

    let encryptedDataT = try? Data(contentsOf: URL(fileURLWithPath: filePath))
    
    guard var encryptedData = encryptedDataT else { return nil }
    
    guard let keyData = Data(fromHexEncodedString: keyHex) else {
        print("Invalid decryption key")
        return nil
    }
    
    guard keyData.count == kCCKeySizeAES256 else {
        print("Invalid key size.")
        return nil
    }

    var decryptedData = Data(count: encryptedData.count + kCCBlockSizeAES128)
    var numBytesDecrypted :size_t = 0
    
    let cryptStatus = keyData.withUnsafeBytes { keyBytes -> CCCryptorStatus in
        encryptedData.withUnsafeBytes { dataBytes -> CCCryptorStatus in
            decryptedData.withUnsafeMutableBytes { decryptedBytes in
                return CCCrypt(CCOperation(kCCDecrypt),
                               CCAlgorithm(kCCAlgorithmAES),
                               CCOptions(kCCOptionPKCS7Padding),
                               keyBytes.baseAddress!,
                               keyData.count,
                               nil, // If needed you can set an IV (Initialization Vector) here
                               dataBytes.baseAddress!,
                               encryptedData.count,
                               decryptedBytes.baseAddress!,
                               decryptedBytes.count,
                               &numBytesDecrypted)
            }
        }
    }
    
    if UInt32(cryptStatus) == UInt32(kCCSuccess) {
        let resultingData = decryptedData.subdata(in: 0..<numBytesDecrypted)
        return String(data: resultingData, encoding: .ascii)
    } else {
        print("Decryption failed with status \(cryptStatus).")
    }
    
    return nil
}

func readEncryptedFile(fileName: String, decryptionKey: String) -> Data? {
    // Read the encrypted file data from disk
    guard let url = URL(string: fileName)
    else {
        return nil
    }

    let justFileName = url.lastPathComponent

    guard let filePath = Bundle.main.path(forResource: justFileName, ofType: nil) else {
        print("File not found in the main bundle")
        return nil
    }
    
    guard let encryptedData = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else {
        print("Failed to read encrypted file")
        return nil
    }
    
    // Convert the decryption key to data
    guard let key = Data(fromHexEncodedString: decryptionKey) else {
        print("Invalid decryption key")
        return nil
    }
    
    // Set up the decryption context
    let bufferSize = encryptedData.count
    var decryptedData = Data(count: bufferSize)
    var numBytesDecrypted: size_t = 0
    
    let keyLength = kCCKeySizeAES256
    let ivSize = kCCBlockSizeAES128
        
    let options = CCOptions(kCCOptionPKCS7Padding)
    
    let status = key.withUnsafeBytes { keyBytes in
        encryptedData.withUnsafeBytes { dataBytes in
            decryptedData.withUnsafeMutableBytes { decryptedBytes in
                CCCrypt(CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        options,
                        keyBytes.baseAddress,
                        keyLength,
                        nil,
                        dataBytes.baseAddress,
                        dataBytes.count,
                        decryptedBytes.baseAddress,
                        decryptedBytes.count,
                        &numBytesDecrypted)
            }
        }
    }
    
    // Check the decryption status
    guard status == kCCSuccess else {
        print("Decryption failed")
        return nil
    }
    
    // Retrieve the actual decrypted data
    let actualDecryptedData = decryptedData.prefix(Int(numBytesDecrypted))
    
    return Data(actualDecryptedData)
}

func removePKCS7Padding(from data: Data) -> Data {
    var paddingLength: UInt8 = 0
    data.copyBytes(to: &paddingLength, from: data.count - 1..<data.count)
    let paddingToRemove = Int(paddingLength)
    let unpaddedData = data.subdata(in: 0..<data.count - paddingToRemove)
    return unpaddedData
}
