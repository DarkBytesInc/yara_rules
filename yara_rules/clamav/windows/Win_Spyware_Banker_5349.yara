rule Win_Spyware_Banker_5349
{
strings:
	$a0 = { 625653f5273a0dc63a2db5c78078f9fab86fd72531e7f66d6fcd47e7d35162c8880d0c693b74347209c6547188dee6e9df38d9b07397090b56379ec9d58f1ce2ae01c2a95445a380514c38fc941e9dfe7449797bbfa460daaaef0a9f5216ef141c89a132fd9ad61b22de6b6d4d98818e04ce621f51ebca5f1608815a0fb5d934927518520c946998c1abfc82bdbc317daec32d230629 }

condition:
	$a0
}

        