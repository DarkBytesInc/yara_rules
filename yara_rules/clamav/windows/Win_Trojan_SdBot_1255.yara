rule Win_Trojan_SdBot_1255
{
strings:
	$a0 = { cc2ee7f961c85db8a3e28d077fe1163499eeee1a8baa8c07af73d3755ddba062ff995d7e7828b641d991c68372cf7b0a21259c7c5ff2587df25843f2d8a8b1c9e31b68ba9c77ff957f706d5d9fcf58a6e5ecadf3ff587d0de178ffd1f0274e44cecc2f7b84ebd2f2eb238e63fa41f6eb3dc6e86d06c7d18edefd2735e0b1366939e41291 }

condition:
	$a0
}

        