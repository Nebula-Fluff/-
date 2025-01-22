// 引用库函数区
#include "src/Ed25519.h"      // 签名函数库
#include "src/SSD1306Wire.h"  // 屏幕驱动函数库
#include "Ticker.h"           // 计时中断函数库

// 硬件或软件初始化区
SSD1306Wire display(0x3c, SDA, SCL);  // 初始化一个OLED显示器实例，指定I2C地址（0x3C），SDA（数据线）和SCL（时钟线）引脚。
Ticker timer;                         // 创建计时实例

// 《定义区》
// 定义代数区
#define SDA 4  // I2C使用引脚设置
#define SCL 5  // I2C使用引脚设置

// -权限码地址数据映射表-
struct BlockMap {
  const uint8_t SelectBlock[4];  // 区块选择标识
  const uint8_t* Data;           // 对应的数据指针
  size_t DataSize;               // 数据长度
};

// 声明数组区
// --可变数组声明区--
uint8_t SystemDataPacket[128];   // 暂存收到的加密数据包
uint8_t TransferData[12];        // 暂存内数据包数据载荷
uint8_t ControlByte[4];          // 暂存控制位
uint8_t RXRandomNum[36];         // 暂存接收到的随机数（挑战）
uint8_t SelectBlock[4];          // 暂存选择权限码地址块数据
String timeout;                  // 超时代码存储区
volatile bool cisrflag = false;  // 通讯超时中断标志位

// --不可变数组声明区--
// -引脚定义-
const int interruptPin1 = 0;

// -钥匙码-
const uint8_t ID[12] = { 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x20, 0x20, 0x20 };  // 存储此密钥的ASCII码ID
const uint8_t KyeEd25519PrivateKey[32] = { 0x7D, 0x6C, 0x95, 0x83, 0xBD, 0x82, 0xE0, 0x76, 0x6E, 0x22, 0xD4, 0xD7, 0xDE, 0x9C, 0xBB, 0xF1,
                                           0x7B, 0xB0, 0xC8, 0xBA, 0x26, 0x72, 0x59, 0x09, 0x70, 0x33, 0x2A, 0x8D, 0xC2, 0x3E, 0x17, 0xE1 };  // 钥匙签名私钥钥
const uint8_t KeyEd25519PubKey[32] = { 0xA8, 0xEA, 0x9C, 0x73, 0xD7, 0x5B, 0x07, 0x44, 0x2B, 0x01, 0x40, 0xB3, 0xDD, 0xF0, 0x0F, 0x6A,
                                       0x23, 0x04, 0xAB, 0x94, 0x27, 0x74, 0xE7, 0x4B, 0x8A, 0xCD, 0x92, 0x12, 0xA9, 0x0C, 0xC8, 0x15 };  // 钥匙签名公钥
const uint8_t AccessManagerEd25519PubKey[32] = { 0x62, 0x32, 0x1B, 0xAE, 0x01, 0x00, 0x07, 0x1C, 0x9B, 0x75, 0x72, 0x82, 0xEB, 0xBD, 0xA5, 0x07,
                                                 0xD1, 0xF0, 0x8E, 0xAA, 0x79, 0x3A, 0x32, 0x29, 0x91, 0xBB, 0xD2, 0xC8, 0x8D, 0x78, 0x4E, 0x6F };  // 验证器签名公钥

// -控制码-
const uint8_t Control1[4] = { 0x00, 0x00, 0x00, 0x01 };  // 控制位1,钥匙让验证器发挑战
const uint32_t Control2[1] = { 0x00000002 };             // 控制位2,包含挑战信息和需要查询的权限码区块
const uint8_t Control3[4] = { 0x00, 0x00, 0x00, 0x03 };  // 控制位3,电子密钥响应签名并交出权限码
const uint32_t Control5[1] = { 0x00000005 };             // 控制位5,验证器告知电子密钥权限为无权限
const uint32_t Control6[1] = { 0x00000006 };             // 控制码6,验证器通知电子密钥权限为User权限
const uint32_t Control7[1] = { 0x00000007 };             // 控制码7,通知电子密钥权限为Manager权限
const uint32_t Control8[1] = { 0x00000008 };             // 控制码8,通知电子密钥权限为Admin权限

// -权限码-
const uint8_t PermissionCodeArea1[12] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };  // 权限码区域1

// -权限码块地址对应-
const BlockMap BlockMapping[] = {
  { { 0x00, 0x00, 0x00, 0x01 }, PermissionCodeArea1, sizeof(PermissionCodeArea1) },
  // 如果有更多区块可以继续添加
};

// -工作状态组-
enum KeyState {
  idle,
  waitcode,
  waitlevel
};

KeyState cstate = idle;  // 初始状态置

// 中断程序-外部中断（验证程序开始）
void ICACHE_RAM_ATTR ISR1() {
  delay(20);        // 消抖
  Start();          // 告诉验证器开始验证流程
  display.clear();  // 清屏
}

// 中断程序-计时器内部中断（通讯恢复状态）
void CTISR() {
  cstate = idle;    // 状态置默认状态
  timer.detach();   // 停止硬件定时器，同时自动触发中断关闭
  cisrflag = true;  //标志位置1
}

void setup() {
  Serial.begin(115200);                                                  // 设置串口波特率为115200
  pinMode(interruptPin1, INPUT_PULLUP);                                  // 设置引脚为输入，并启用上拉电阻
  attachInterrupt(digitalPinToInterrupt(interruptPin1), ISR1, FALLING);  // 在下降沿触发中断
  display.init();                                                        // 初始化显示器，确保显示屏已经准备好工作。
  display.setFont(ArialMT_Plain_10);                                     // 设置显示器的默认字体为ArialMT_Plain_10，大小为10px。
}

void loop() {
  display.drawString(0, 0, "READY  KeyID:Root Key");  // 显示钥匙ID
  display.display();                                  // 显示

  if (cisrflag) {
    cisrflag = false;
    display.drawString(0, 10, "ConnectionTimeout");  // 显示通讯超时
    display.drawString(0, 20, timeout);              // 显示超时代码
    display.display();                               // 显示
    block(1000);                                     // 阻塞1秒
    display.clear();                                 //  清屏
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
  memcpy(ControlByte, &SystemDataPacket[124], 4);  // 将控制位挪到控制位格式转换区
  Control();                                       // 进入读取控制位分配任务函数
}

// 读取控制并分配相应任务
void Control() {
  uint32_t Control4Byte[1];                                                                                    // 暂存转换后的控制位
  Control4Byte[0] = (ControlByte[0] << 24) | (ControlByte[1] << 16) | (ControlByte[2] << 8) | ControlByte[3];  // 转换控制位格式为uint32_t
  if (Control4Byte[0] == Control2[0] && cstate == waitcode) {
    Control4Byte[0] = 0x00000000;  // 清空控制位信息
    SendPermissionCode();          // 进入发送权限码函数
  } else if (Control4Byte[0] == Control5[0] && cstate == waitlevel) {
    Control4Byte[0] = 0x00000000;                // 清空控制位信息
    cstate = idle;                               // 状态置默认状态
    timer.detach();                              // 停止硬件定时器，同时自动触发中断关闭
    display.drawString(0, 10, "No Permission");  // 屏幕提示无权限
    display.display();                           // 显示
    block(2000);                                 // 阻塞两秒
    disclearblock(0, 10, 128, 10);               // 清理相应位置屏幕信息
  } else if (Control4Byte[0] == Control6[0] && cstate == waitlevel) {
    Control4Byte[0] = 0x00000000;                      // 清空控制位信息
    cstate = idle;                                     // 状态置默认状态
    timer.detach();                                    // 停止硬件定时器，同时自动触发中断关闭
    display.drawString(0, 10, "Access Level:User");    // 屏幕提示权限
    display.drawString(0, 20, "Verification Passed");  // 屏幕提示验证通过
    display.display();                                 // 显示
    block(2000);                                       // 阻塞两秒
    disclearblock(0, 10, 128, 20);                     // 清理相应位置屏幕信息
  } else if (Control4Byte[0] == Control7[0] && cstate == waitlevel) {
    Control4Byte[0] = 0x00000000;                       // 清空控制位信息
    cstate = idle;                                      // 状态置默认状态
    timer.detach();                                     // 停止硬件定时器，同时自动触发中断关闭
    display.drawString(0, 10, "Access Level:Manager");  // 屏幕提示权限
    display.drawString(0, 20, "Verification Passed");   // 屏幕提示验证通过
    display.display();                                  // 显示
    block(2000);                                        // 阻塞两秒
    disclearblock(0, 10, 128, 20);                      // 清理相应位置屏幕信息
  } else if (Control4Byte[0] == Control8[0] && cstate == waitlevel) {
    Control4Byte[0] = 0x00000000;                      // 清空控制位信息
    cstate = idle;                                     // 状态置默认状态
    timer.detach();                                    // 停止硬件定时器，同时自动触发中断关闭
    display.drawString(0, 10, "Access Level:Admin");   // 屏幕提示权限
    display.drawString(0, 20, "Verification Passed");  // 屏幕提示验证通过
    display.display();                                 // 显示
    block(2000);                                       // 阻塞两秒
    disclearblock(0, 10, 128, 20);                     // 清理相应位置屏幕信息
  }
}

// 告诉验证器开始验证流程
void Start() {
  uint8_t ToBeSendDataPacket[128] = { 0 };        // 暂存需要发送的外数据包
  memcpy(&ToBeSendDataPacket[124], Control1, 4);  // 加入控制位数据
  cstate = waitcode;                              // 改变状态
  timeout = "start";                              // 改变状态（用于报错显示）
  Serial.write(ToBeSendDataPacket, 128);          // 发送数据包
  timer.attach(1, CTISR);                         // 硬件定时器设置，自动触发中断回到默认状态
}

// 查看接收的数据缓存发送相应的权限码
void SendPermissionCode() {
  timer.detach();                                 // 停止硬件定时器，同时自动触发中断关闭
  uint8_t ToBeSendDataPacket[128] = { 0 };        // 暂存需要发送的外数据包
  uint8_t ToBeSignature[64] = { 0 };              // 整理好的数据存放处
  uint8_t Signature[64] = { 0 };                  // 签名好的数据存放处
  uint8_t PermissionCodeBuffer[12] = { 0 };       // 取出的权限码
  memcpy(RXRandomNum, SystemDataPacket, 36);      // 将挑战随机数存起来
  memcpy(SelectBlock, &SystemDataPacket[36], 4);  // 将权限码区块选择数据暂存
  // 遍历区块映射表，寻找匹配的选择数据
  for (size_t i = 0; i < sizeof(BlockMapping) / sizeof(BlockMap); ++i) {
    if (memcmp(SelectBlock, BlockMapping[i].SelectBlock, 4) == 0) {
      // 找到对应区块，复制数据到发送缓冲区
      memcpy(PermissionCodeBuffer, BlockMapping[i].Data, BlockMapping[i].DataSize);
      break;
    }
  }

  memcpy(ToBeSignature, PermissionCodeBuffer, 12);  // 将权限码移入待签名区
  memcpy(&ToBeSignature[12], ID, 12);               // 将ID号移入待签名区
  memcpy(&ToBeSignature[24], RXRandomNum, 36);      // 将随机数移入待签名区
  memcpy(&ToBeSignature[60], Control3, 4);          // 将控制位移入待签名区

  Ed25519::sign(Signature, KyeEd25519PrivateKey, KeyEd25519PubKey, ToBeSignature, 64);  // 签名数据

  memcpy(ToBeSendDataPacket, Signature, 64);           // 加入签名
  memcpy(&ToBeSendDataPacket[64], ToBeSignature, 64);  // 加入数据
  cstate = waitlevel;                                  // 改变状态
  timeout = "spc";                                     // 改变状态（用于报错显示）
  Serial.write(ToBeSendDataPacket, 128);               // 发送数据包
  timer.attach(1, CTISR);                              // 硬件定时器设置，自动触发中断回到默认状态
}

// 清屏特定区域函数
void disclearblock(int x, int y, int width, int height) {
  display.setColor(BLACK);                // 设置颜色
  display.fillRect(x, y, width, height);  // 从什么地方开始填充多宽多高的区域
  display.display();                      // 显示
  display.setColor(WHITE);                // 设置颜色
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