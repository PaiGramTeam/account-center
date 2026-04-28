package model

const (
	ConsumerPaiGramBot = "paigram-bot"
	ConsumerPamgram    = "pamgram"
)

var SupportedConsumers = []string{ConsumerPaiGramBot, ConsumerPamgram}

func ConsumerForBotID(botID string) (string, bool) {
	switch botID {
	case "bot-paigram", ConsumerPaiGramBot:
		return ConsumerPaiGramBot, true
	case "bot-pamgram", ConsumerPamgram:
		return ConsumerPamgram, true
	default:
		return "", false
	}
}
