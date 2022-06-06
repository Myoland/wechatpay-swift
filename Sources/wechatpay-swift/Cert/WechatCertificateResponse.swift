import Foundation

struct WechatCertificateResponse: Codable {
  struct Data: Codable {
    struct EncryptCertificate: Codable {
      let algorithm: String
      let associatedData: String
      let ciphertext: String
      let nonce: String

      private enum CodingKeys: String, CodingKey {
        case algorithm
        case associatedData = "associated_data"
        case ciphertext
        case nonce
      }
    }

    let effectiveTime: Date
    let encryptCertificate: EncryptCertificate
    let expireTime: Date
    let serialNo: String

    private enum CodingKeys: String, CodingKey {
      case effectiveTime = "effective_time"
      case encryptCertificate = "encrypt_certificate"
      case expireTime = "expire_time"
      case serialNo = "serial_no"
    }
  }

  let data: [Data]
}
