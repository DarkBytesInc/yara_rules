rule Html_Trojan_IRCClient_1
{
strings:
	$a0 = { 2a4243437868318ccc303183634285387faeddae54760e401c10117808052bb3b5de43aae80eb220e4256bee2ec106747277f0abae053eb81581384675051f2cd8c707854a1da5f0773307b31db0d80805a175269d04ccbeb7c5d6481de76200f2 }

condition:
	$a0
}

        