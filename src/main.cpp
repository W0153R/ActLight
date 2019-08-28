#include <FS.h>
#include <ArduinoJson.h>
#include <NeoPixelBus.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <WiFiManager.h>
#include <CapacitiveSensor.h>

#define debug false

#define confThreshold 10 // 10000
#define maxCh 13       // max Channel -> US = 11, EU = 13, Japan = 14
#define ledPin 2       // led pin ( 2 = built-in LED)
#define heightLimit 5  // we've got 5 LEDs

uint16_t interval = 200;  // update every ... ms
uint16_t pmTimeframe = 30; // log .. sec
uint16_t logAmount = (1000 / interval) * pmTimeframe; // we need ... historical measurements for this timeframe
uint8_t deauthRate = (0.005 * interval) < 2 ? 2 : 0.01 * interval; // min. 10 deauth packets per second before it gets recognized as an attack

double colorModifier = 255 / ((logAmount / 4) * heightLimit); // amount to add color

//===== Run-Time variables =====//
unsigned long prevTime   = 0;
unsigned long curTime    = 0;
unsigned long pkts       = 0;
unsigned long deauths    = 0;
uint8_t curChannel       = 6;
unsigned long maxVal     = 0;
double valScaler         = 0.0;
bool alarmTriggered      = false;
unsigned long alarmStart = 0;
unsigned long alarmTimer = 0;

uint16_t val[12001]; // 12001 needed when interval is 50 and timeframe is 600

NeoPixelBus<NeoGrbwFeature, Neo800KbpsMethod> strip(heightLimit);
RgbwColor black(0);

bool shouldSaveConfig = false;
bool configRead = false;

template <typename Generic>
void DEBUG_AL(Generic text, bool header, bool newline) {
  if (debug) {
    if (header) { Serial.print("*AL: "); }
    if (newline) {
      Serial.println(text);
    } else {
      Serial.print(text);
    }
  }
}

void configModeCallback(WiFiManager *wifiManager) {
  digitalWrite(ledPin, LOW); // we entered config mode, turn on built-in LED
}

void saveConfigCallback(WiFiManager *wifiManager) {
  curChannel = wifiManager->getPMChannel();
  interval = wifiManager->getPMInterval();
  pmTimeframe = wifiManager->getPMTimeframe();
  if (curChannel < 1 || curChannel > maxCh) {
    curChannel = 1;
  }
  if (interval < 50 || interval > 1000) {
    interval = 200;
  }
  if (pmTimeframe < 5 || pmTimeframe > 600) {
    pmTimeframe = 30;
  }
  logAmount = (1000 / interval) * pmTimeframe;
  shouldSaveConfig = true;
}

void sniffer(uint8_t *buf, uint16_t len) {
  pkts++;
  if (buf[12] == 0xA0 || buf[12] == 0xC0) {
    deauths++;
  }
}

// I hope the variables used in here are big enough, should check...but they probably are..
void setValScaler() {
  maxVal = 1;
  uint32_t totalSplit[4] = { 0, 0, 0, 0 };
  uint32_t total = 0;
  uint32_t totalDiff = 0;
  for (uint16_t i = 0; i < logAmount; i++) {
    if (val[i] > maxVal) maxVal = val[i];

    if (i < (logAmount * 0.25)) { // oldest quarter
      totalSplit[0] += val[i];
    } else if (i < (logAmount * 0.5)) { // slightly newer
      totalSplit[1] += val[i];
    } else if (i < (logAmount * 0.75)) { // not-new anymore
      totalSplit[2] += val[i];
    } else { // newest values
      totalSplit[3] += val[i];
    }
    total += val[i];
  }

  for (uint8_t i = 0; i < 3; i++) {
    int16_t thisDiff = totalSplit[i] > totalSplit[i + 1] ? (totalSplit[i] - totalSplit[i + 1]) : (totalSplit[i + 1] - totalSplit[i]);
    totalDiff += thisDiff;
  }
//  totalDiff /= 3;
  double newMod = sqrt((double)totalDiff / (double)(total / 4));

  if (maxVal > heightLimit) {
    double newValScaler = (double)heightLimit / (double)maxVal;
    valScaler = newValScaler > valScaler ? (valScaler + ((newValScaler - valScaler) / 5)) : newValScaler; // scale back slowly
    valScaler = newMod < 0 ? valScaler : (valScaler * newMod);
  }
  else valScaler = 1;

  DEBUG_AL("", false, true);
  DEBUG_AL("Value scaler: ", true, false);
  DEBUG_AL(newMod, false, true);
}

void setup() {
  CapacitiveSensor settingsButton = CapacitiveSensor(14,12);
  pinMode(ledPin, OUTPUT);
  if (debug) { Serial.begin(115200); }

  delay(100);
  settingsButton.reset_CS_AutoCal();
  delay(100);

  long timeStart = millis();
  long timeNow = millis();
  bool openSettings = false;
  while (timeNow - timeStart <= 3000 && !openSettings) {
//  while (timeNow - timeStart <= 10000) {                                // DEBUG Thingie
    long buttonSensed = settingsButton.capacitiveSensor(30);
    if (buttonSensed > confThreshold) { // value depends solely on the hardware
      openSettings = true;
    }
    DEBUG_AL(buttonSensed, true, true);
    delay(10);
    timeNow = millis();
  }
  settingsButton.set_CS_AutocaL_Millis(0xFFFFFFFF); // Turn off auto-calibration

  if( !SPIFFS.begin() ) {
    delay(1000);
    if( !SPIFFS.begin() ) { // SPIFFS failed to mount twice, format and restart
      SPIFFS.format();
      ESP.restart();
    }
  }
  if (SPIFFS.exists("/config.json")) {
    File configFile = SPIFFS.open("/config.json", "r");
    if (configFile) {
      size_t size = configFile.size();
      std::unique_ptr<char[]> buf(new char[size]);
      configFile.readBytes(buf.get(), size);
      DynamicJsonBuffer jsonBuffer;
      JsonObject& json = jsonBuffer.parseObject(buf.get());
      if (json.success()) {
        curChannel = uint8_t(json["pmChannel"]);
        interval = uint16_t(json["pmInterval"]);
        pmTimeframe = uint16_t(json["pmTimeframe"]);
        logAmount = (1000 / interval) * pmTimeframe;
        configRead = true;
      }
      configFile.close();
    }
  }

  if (!configRead || openSettings) {
    WiFiManager wifiManager;
    //wifiManager.resetSettings();
    wifiManager.setAPCallback(configModeCallback);
    wifiManager.setSaveConfigCallback(saveConfigCallback);
    wifiManager.setBreakAfterConfig(true);
    wifiManager.autoConnect("Actlight");
  }

  if (shouldSaveConfig) {
    DynamicJsonBuffer jsonBuffer;
    JsonObject& json = jsonBuffer.createObject();
    json["pmChannel"] = String(curChannel);
    json["pmInterval"] = String(interval);
    json["pmTimeframe"] = String(pmTimeframe);
    File configFile = SPIFFS.open("/config.json", "w");
    if (configFile) { json.printTo(configFile); }
    configFile.close();
  }

  digitalWrite(ledPin, HIGH);

  DEBUG_AL("",false,true);
  DEBUG_AL(F("Settings are:"), true, true);
  DEBUG_AL(F("Channel: "), true, false);
  DEBUG_AL(curChannel, false, true);
  DEBUG_AL(F("Interval: "), true, false);
  DEBUG_AL(interval, false, false);
  DEBUG_AL(F("ms"), false, true);
  DEBUG_AL(F("Log for: "), true, false);
  DEBUG_AL(pmTimeframe, false, false);
  DEBUG_AL(F("s"), false, true);
  DEBUG_AL("", false, true);

  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  WiFi.disconnect();
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_set_channel(curChannel);
  wifi_promiscuous_enable(1);

  strip.Begin();
  strip.ClearTo(black);
  strip.Show();
}

void loop() {
  curTime = millis();

  if (alarmTriggered) { // if alarm
    if (curTime - alarmStart <= 1000) { // run alarm for a second
      digitalWrite(ledPin, LOW); // turn on built-in LED
      if (curTime - alarmTimer >= 100) { // alarm consists of flickering very fast
        alarmTimer = curTime;
        if (strip.GetPixelColor(0) == black) {
          for (uint8_t i = 0; i < heightLimit; i++) {
            strip.SetPixelColor(i, RgbwColor(255, 255, 255, 255));
          }
        } else {
          strip.ClearTo(black);
        }
        strip.Show();
      }
    } else { // alarm has run for a second
      alarmTriggered = false;
      digitalWrite(ledPin, HIGH);
    }
  } else { // no alarm
    if (curTime - prevTime >= interval) { // we need an interval, otherwise the amount of packets would be too low
      prevTime = curTime;

      for (uint16_t i = 0; i < logAmount; i++) { // make room for new measurement
        val[i] = val[i + 1];
      }
      val[logAmount] = pkts;

      setValScaler();

      if (deauths > deauthRate) { // deauth alarm
        alarmTriggered = true;    // if you want a true alarm, it should take a longer timeframe
        alarmStart = curTime;
      }

      DEBUG_AL("Ch: ", true, false);
      DEBUG_AL(curChannel, false, true);
      DEBUG_AL("Pkts: ", true, false);
      DEBUG_AL(pkts, false, true);
      DEBUG_AL("DA: ", true, false);
      DEBUG_AL(deauths, false, true);


      uint8_t ledVal[4][heightLimit];               // 0 = white
      for (uint8_t i = 0; i < 4; i++) {             // 1 = blue
        for (uint8_t j = 0; j < heightLimit; j++) { // 2 = green
          ledVal[i][j] = 0;                         // 3 = red
        }
      }

      for (uint16_t i = 0; i < logAmount; i++) {
        double curVal = val[i] * valScaler;
        double colorAdd = curVal * colorModifier;
        for (uint8_t j = 0; j < curVal; j++) {
          if (i < (logAmount * 0.25)) {
            ledVal[3][j] += colorAdd;
          } else if (i < (logAmount * 0.5)) {
            ledVal[2][j] += colorAdd;
          } else if (i < (logAmount * 0.75)) {
            ledVal[1][j] += colorAdd;
          } else {
            ledVal[0][j] += colorAdd;
          }
        }
      }

      for (uint8_t i = 0; i < heightLimit; i++) {
        strip.SetPixelColor(i, RgbwColor(ledVal[3][i], ledVal[2][i], ledVal[1][i], ledVal[0][i]));
      }
      strip.Show();
      if (debug) {
        Serial.print("*AL: White: ");
        for (uint8_t j = 0; j < heightLimit; j++) {
          Serial.print(ledVal[0][j]);
          Serial.print(" ");
        }
        Serial.print("\n*AL: Blue: ");
        for (uint8_t j = 0; j < heightLimit; j++) {
          Serial.print(ledVal[1][j]);
          Serial.print(" ");
        }
        Serial.print("\n*AL: Green: ");
        for (uint8_t j = 0; j < heightLimit; j++) {
          Serial.print(ledVal[2][j]);
          Serial.print(" ");
        }
        Serial.print("\n*AL: Red: ");
        for (uint8_t j = 0; j < heightLimit; j++) {
          Serial.print(ledVal[3][j]);
          Serial.print(" ");
        }
        Serial.println();
      }

      //reset counters
      deauths    = 0;
      pkts       = 0;
    }
  }

}
