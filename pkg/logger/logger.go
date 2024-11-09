package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

var SugarLog *zap.SugaredLogger

func Initialize(debug bool) {
	var opts []zap.Option
	var encoderConfig zapcore.EncoderConfig
	atomicLevel := zap.NewAtomicLevel()
	if debug {
		atomicLevel.SetLevel(zap.DebugLevel)
		encoderConfig = zapcore.EncoderConfig{
			MessageKey: "msg",
			LevelKey:   "level",
			TimeKey:    "ts",
			NameKey:    "logger",
			//CallerKey:      "caller",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseColorLevelEncoder,
			EncodeTime:     zapcore.RFC3339TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		}
		opts = append(opts, zap.AddCaller(), zap.AddStacktrace(zapcore.DPanicLevel))
	} else {
		atomicLevel.SetLevel(zap.InfoLevel)
		encoderConfig = zapcore.EncoderConfig{
			MessageKey:  "msg",
			LevelKey:    "level",
			EncodeLevel: zapcore.CapitalColorLevelEncoder,
		}
	}
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.Lock(os.Stdout),
		atomicLevel,
	)
	logger := zap.New(core, opts...)
	defer logger.Sync()
	SugarLog = logger.Sugar()
}
