// 引用库函数区
#include "src/Ed25519.h"      // 签名函数库
#include "src/SSD1306Wire.h"  // 屏幕驱动函数库
#include <Ticker.h>       // 计时中断函数库
#include "src/RNG.h"          // 随机数生成函数库

// 硬件或软件初始化区
SSD1306Wire display(0x3c, SDA, SCL);  // 初始化一个OLED显示器实例，指定I2C地址（0x3C），SDA（数据线）和SCL（时钟线）引脚。
Ticker timer;                         // 创建计时实例

// 《定义区》
// 定义代数区
#define PACKET_HEADER1 0xAA      // 包头第1字节用于验证
#define PACKET_HEADER2 0x55      // 包头第2字节用于验证
#define PACKET_TAIL1 0x55        // 包尾第1字节用于验证
#define PACKET_TAIL2 0xAA        // 包尾第2字节用于验证
#define SDA 4                    // I2C使用引脚设置
#define SCL 5                    // I2C使用引脚设置
#define NO_PERMISSION 0B00       // 无权限对应的编码
#define USER_PERMISSION 0B01     // 用户权限对应的编码
#define MANAGER_PERMISSION 0B10  // 经理权限对应的编码
#define ADMIN_PERMISSION 0B11    // 管理员权限对应的编码

// 声明数组区
// --可变数组声明区--
uint8_t SystemDataPacket[128];   // 暂存收到的加密数据包
uint8_t TransferData[12];        // 暂存内数据包数据载荷
uint8_t ControlByte[4];          // 暂存控制位
uint8_t RandomNum[36];           // 暂存随机数
uint8_t SelectBlock[4];          // 暂存选择权限码地址块数据
String timeout;                  // 超时代码存储区
volatile bool cisrflag = false;  // 通讯超时中断标志位
volatile bool aisrflag = false;  // 权限超时中断标志位
uint8_t GetID[12];               // 暂存收到的ID

// --不可变数组声明区--
// -钥匙码-
const uint8_t ID[12] = { 0x43, 0x6F, 0x72, 0x65, 0x20, 0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65 };  // 存储此验证器的ID
const uint8_t KeyEd25519PubKey[32] = { 0xA8, 0xEA, 0x9C, 0x73, 0xD7, 0x5B, 0x07, 0x44, 0x2B, 0x01, 0x40, 0xB3, 0xDD, 0xF0, 0x0F, 0x6A,
                                       0x23, 0x04, 0xAB, 0x94, 0x27, 0x74, 0xE7, 0x4B, 0x8A, 0xCD, 0x92, 0x12, 0xA9, 0x0C, 0xC8, 0x15 };  // 钥匙签名公钥
const uint8_t AccessManagerEd25519PrivateKey[32] = { 0x18, 0x39, 0xE6, 0xEC, 0xC8, 0x0F, 0x76, 0xCD, 0xEF, 0x37, 0x8E, 0x98, 0xAA, 0x9E, 0x03, 0x5D,
                                                     0x2D, 0x59, 0xC6, 0x10, 0x02, 0x97, 0x66, 0x4F, 0x86, 0xF4, 0xCC, 0x8F, 0x91, 0x75, 0xCB, 0xDF };  // 验证器签名私钥
const uint8_t AccessManagerEd25519PubKey[32] = { 0x62, 0x32, 0x1B, 0xAE, 0x01, 0x00, 0x07, 0x1C, 0x9B, 0x75, 0x72, 0x82, 0xEB, 0xBD, 0xA5, 0x07,
                                                 0xD1, 0xF0, 0x8E, 0xAA, 0x79, 0x3A, 0x32, 0x29, 0x91, 0xBB, 0xD2, 0xC8, 0x8D, 0x78, 0x4E, 0x6F };  // 验证器签名公钥

// -控制码-
const uint32_t Control1[1] = { 0x00000001 };             // 控制位1,钥匙发送的开始验证请求
const uint8_t Control2[4] = { 0x00, 0x00, 0x00, 0x02 };  // 控制位2,验证器回应验证开始,发送取权限码地址
const uint32_t Control3[1] = { 0x00000003 };             // 控制位3,密钥发送对应的权限码
const uint8_t Control5[4] = { 0x00, 0x00, 0x00, 0x05 };  // 控制位5,验证器告知电子密钥权限为无权限
const uint8_t Control6[4] = { 0x00, 0x00, 0x00, 0x06 };  // 控制码6,验证器通知电子密钥权限为User权限
const uint8_t Control7[4] = { 0x00, 0x00, 0x00, 0x07 };  // 控制码7,通知电子密钥权限为Manager权限
const uint8_t Control8[4] = { 0x00, 0x00, 0x00, 0x08 };  // 控制码8,通知电子密钥权限为Admin权限

// -所需权限地址-
const uint8_t Address[4] = { 0x00, 0x00, 0x00, 0x01 };  // 所需权限码在钥匙内的地址(多了可以编写表格查表)

// -通讯所需-
const uint8_t Header[2] = { 0xAA, 0x55 };  // 数据包包头用于发送函数
const uint8_t Tail[2] = { 0x55, 0xAA };    // 数据包包尾用于发送函数

// 枚举状态库
enum VState {
  idle,
  waitcode,
  user,
  manager,
  admin
};

VState cstate = idle;  // 初始状态置

// 中断程序-计时器内部中断（通讯恢复状态）
void CTISR() {
  cstate = idle;    // 状态置默认状态
  timer.detach();   // 停止硬件定时器，同时自动触发中断关闭
  cisrflag = true;  //标志位置1
}

// 中断程序-计时器内部中断（通讯恢复状态）
void ATISR() {
  cstate = idle;    // 状态置默认状态
  timer.detach();   // 停止硬件定时器，同时自动触发中断关闭
  aisrflag = true;  // 标志位置1
}

void setup() {
  Serial.begin(115200);               // 设置串口波特率为115200
  RNG.begin("ID:0x00");               // 随机数生成器初始化
  display.init();                     // 初始化显示器，确保显示屏已经准备好工作。
  display.setFont(ArialMT_Plain_10);  // 设置显示器的默认字体为ArialMT_Plain_10，大小为10px。
}

void loop() {
  display.drawString(0, 0, "Core Console");
  display.display();

  if (cisrflag) {
    cisrflag = false;
    display.clear();                                 //  清屏
    display.drawString(0, 10, "ConnectionTimeout");  // 显示通讯超时
    display.drawString(0, 20, timeout);              // 显示超时代码
    display.display();                               // 显示
    block(2000);                                     // 阻塞两秒
    display.clear();                                 //  清屏
  } else if (aisrflag) {
    aisrflag = false;
    display.clear();                              //  清屏
    display.drawString(0, 10, "Access Expired");  // 显示授权过期
    display.display();                            // 显示
    block(2000);                                  // 阻塞两秒
    display.clear();                              //  清屏
  }
  // 接收数据函数段
  else if (Serial.available() >= 128) {
    delay(10);                                // 等待数据发完
    Serial.readBytes(SystemDataPacket, 128);  // 将缓冲区内数据包放到数组内方便处理
    while (Serial.read() >= 0) {}             // 清掉串口缓存
    ProcessSystemPacket();                    // 进入数据包处理函数
  }
}

// 处理内数据包函数
void ProcessSystemPacket() {
  uint8_t ToVerifySignature[64] = { 0 };             // 创建数据分类块
  uint8_t ToVerifyUnsignedOriginalData[64] = { 0 };  // 创建数据分类块
  uint8_t a[4] = { 0x00, 0x00, 0x00, 0x01 };         // 初始状态对比块
  if (memcmp(a, &SystemDataPacket[124], 4) == 0) {
    CheckCode();  // 进入发送需要检查的权限码块地址函数
  }
  memcpy(ToVerifySignature, SystemDataPacket, 64);                                                        // 给数据分类存放
  memcpy(ToVerifyUnsignedOriginalData, &SystemDataPacket[64], 64);                                        // 给数据分类存放
  memcpy(&ToVerifyUnsignedOriginalData[24], RandomNum, 36);                                               // 给数据分类存放
  bool isValid = Ed25519::verify(ToVerifySignature, KeyEd25519PubKey, ToVerifyUnsignedOriginalData, 64);  // 将分类好的数据进行验证
  if (isValid) {
    memcpy(ControlByte, &SystemDataPacket[124], 4);  // 将控制位挪到控制位格式转换区
    Control();                                       // 进入读取控制位分配任务函数
  }
}

void Control() {
  uint32_t Control4Byte[1];                                                                                    // 暂存转换后的控制位
  Control4Byte[0] = (ControlByte[0] << 24) | (ControlByte[1] << 16) | (ControlByte[2] << 8) | ControlByte[3];  // 转换控制位格式为uint32_t
  if (Control4Byte[0] == Control3[0] && cstate == waitcode) {
    VerifyCode();  // 进入验证验证权限码函数
  }
}

void CheckCode() {
  uint8_t ToBeSendDataPacket[128] = { 0 };        // 暂存需要发送的外数据包
  RNG.rand(RandomNum, sizeof(RandomNum));         // 生成挑战随机数
  memcpy(ToBeSendDataPacket, RandomNum, 36);      // 将挑数据送入发送区
  memcpy(&ToBeSendDataPacket[36], Address, 4);    // 将挑数据送入发送区
  memcpy(&ToBeSendDataPacket[124], Control2, 4);  // 将挑数据送入发送区
  cstate = waitcode;                              // 改变当前状态
  timeout = "check";                              // 改变当前状态（用于报错显示）
  Serial.write(ToBeSendDataPacket, 132);          // 发送数据包
  timer.attach(1, CTISR);                         // 硬件定时器设置，自动触发中断回到默认状态
}

void VerifyCode() {
  timer.detach();                                            // 停止硬件定时器，同时自动触发中断关闭
  uint8_t PermissionCode[12] = { 0 };                        // 暂存需验证的权限码
  memcpy(PermissionCode, &SystemDataPacket[64], 12);         // 转移权限码
  if ((PermissionCode[0] & 0B00000011) == ADMIN_PERMISSION)  // 验证是否为管理员权限
  {
    display.drawString(0, 10, "Access Level:Admin");                  // 屏幕提示权限
    display.display();                                                // 显示
    uint8_t ToBeSendDataPacket[128] = { 0 };                          // 暂存需要发送的外数据包
    memcpy(&ToBeSendDataPacket[124], Control8, 4);                    // 发送反馈告诉密钥权限等级
    Serial.write(ToBeSendDataPacket, 128);                            // 发送数据包
    cstate = admin;                                                   // 改变当前状态
    timer.attach(2, ATISR);                                           // 硬件定时器设置，自动触发中断回到默认状态
  } else if ((PermissionCode[0] & 0B00000011) == MANAGER_PERMISSION)  // 验证是否为管经理权限
  {
    display.drawString(0, 10, "Access Level:Manager");             // 屏幕提示权限
    display.display();                                             // 显示
    uint8_t ToBeSendDataPacket[128] = { 0 };                       // 暂存需要发送的外数据包
    memcpy(&ToBeSendDataPacket[124], Control7, 4);                 // 发送反馈告诉密钥权限等级
    Serial.write(ToBeSendDataPacket, 128);                         // 发送数据包
    cstate = manager;                                              // 改变当前状态
    timer.attach(2, ATISR);                                        // 硬件定时器设置，自动触发中断回到默认状态
  } else if ((PermissionCode[0] & 0B00000011) == USER_PERMISSION)  // 验证是否为用户权限
  {
    display.drawString(0, 10, "Access Level:User");  // 屏幕提示权限
    display.display();                               // 显示
    uint8_t ToBeSendDataPacket[128] = { 0 };         // 暂存需要发送的外数据包
    memcpy(&ToBeSendDataPacket[124], Control6, 4);   // 发送反馈告诉密钥权限等级
    Serial.write(ToBeSendDataPacket, 128);           // 发送数据包
    cstate = user;                                   // 改变当前状态
    timer.attach(2, ATISR);                          // 硬件定时器设置，自动触发中断回到默认状态
  } else {
    display.drawString(0, 10, "No Permission");     // 屏幕提示权限
    display.display();                              // 显示
    uint8_t ToBeSendDataPacket[132] = { 0 };        // 暂存需要发送的外数据包
    memcpy(&ToBeSendDataPacket[124], Control5, 4);  // 发送反馈告诉密钥权限等级
    Serial.write(ToBeSendDataPacket, 128);          // 发送数据包
    cstate = idle;                                  // 改变当前状态
    block(1000);                                    // 阻塞一秒
    display.clear();                                //  清屏
  }
}

// 防止引发后台看门狗触发重启的阻塞函数
void block(int input) {
  unsigned long startTime = millis();     // 记录开始时间
  unsigned long lastYield = millis();     // 上次调用yield的时间
  while (millis() - startTime < input) {  // 判断已经过去了多少毫秒
    if (millis() - lastYield >= 10) {     // 每10毫秒调用一次yield
      yield();                            // 执行底层代码，避免看门狗叫
      lastYield = millis();               // 转移数据为执行判断
    }
  }
}