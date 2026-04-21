package model

const ConsumerPaiGramBot = "paigram-bot"

var SupportedConsumers = []string{ConsumerPaiGramBot}

func ConsumerForBotID(botID string) (string, bool) {
	switch botID {
	case "bot-paigram", ConsumerPaiGramBot:
		return ConsumerPaiGramBot, true
	default:
		return "", false
	}
}
