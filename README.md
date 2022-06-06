# wechatpay-swift

微信支付 V3 API 的 Swift SDK，自动化了加密 & 解密过程

目前支持了 H5API

## 使用

1. 初始化 WechatPay 

```swift
let wechatPay = WechatPay(
    apiV3Secret: "",
    certificatePath: "",
    wxCertificatePath: "",
    mchid: "",
    serialNo: "")
```

2. 调用 H5API 进行下单

```swift
let request = WechatPay.H5API.PrepayRequest(
    mchid: "",
    description: "Test Product",
    outTradeNo: "",
    notifyURL: "",
    amount:  WechatPay.H5API.PrepayRequest.Amount(total: 6800),
    appid: "",
    sceneInfo: WechatPay.H5API.PrepayRequest.SceneInfo(
                payerClientIp: "127.0.0.1",
                h5Info: WechatPay.H5API.PrepayRequest.SceneInfo.H5Info(type: "Wap")))

let client = WechatPay.H5API(wechatPay: wechatPay)

let h5Response = try await client.prepayWithRequestPayment(request: request)
```

## H5API 

- 预下单 prepayWithRequestPayment
- 查询订单 queryTransactionWithTradeNo
- 解析微信支付通知 decodeNotification 
