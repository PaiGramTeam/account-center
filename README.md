# Paigram Account Center

用户中心系统，为 PaiGram 系列机器人提供集中的用户数据管理，同时为终端用户提供账号管理界面。

## Legacy Bot Binding Writes

`BotAccessService.UpsertPlatformBinding` is migration-only. Normal bot runtime must use `ResolveBotUser`, `ListAccessibleBindings`, and `IssueServiceTicket`. New platform account ownership is created through account-center self-service or admin APIs and orchestrated to platform services.
