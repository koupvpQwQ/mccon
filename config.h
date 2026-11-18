#pragma once

struct PadConfig
{
    // ゲーム内部のデッドゾーン閾値(バニラは約0.3978)
    float deadzone = 0.0f;
};

PadConfig& Config();

// 現在の設定値をゲームへ反映する
bool Config_Apply();