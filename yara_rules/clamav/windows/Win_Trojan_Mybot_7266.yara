rule Win_Trojan_Mybot_7266
{
strings:
	$a0 = { cbad5fb12ce03a4e0a780c18b07cef603347f5d938ecc108a745f43745573fce7408c82a64e34caebeb4ca3c0916ccfd227c6d964e87dccb2c900925bdd9c810a5339912ab9ab49aa4cf4e77af92c5a97465679ca1b473bacd7bf90b0ca978c6f65e3bc687fc0fa9ddfbf558fe2cfc162ed2725ff39289a8f366b8 }

condition:
	$a0
}

        
