# 正在更新中 有诸多细节问题 并且项目处于混乱状态
# 基于ArduinoIDE的ESP8266身份验证系统
## 接线
SDA-D2(GPIO4)
SCL-D1(GPIO5)
TXD-RXD
RXD-TXD
GND-GND
## 简介
使用Ed25519签名来核实身份以及数据包是否被篡改，从而使简单的权限码能够比较安全
## 数据包结构
### simple alpha0.1密钥发出:
SystemDataPacket:  
Signature(64Byte)+PermissionCode(12Byte)+keyID(12Byte)+RandomNum(36Byte)+Control(4Byte)  
ToBeSignature:  
PermissionCode(12Byte)+keyID(12Byte)+RandomNum(36Byte)+Control(4Byte)
### simple alpha0.1验证器发出:
SystemDataPacket:  
EmptyData(36Byte)+
