rule Win_Trojan_IRCBot_333
{
strings:
	$a0 = { 07a915bb446b625f6b09d1aed3e5984652844f397b7533988633698ba3281b185118949e70880d00fdf7b93bed78ebf2203932e47726ea2e0300413e0fcc8467ad3cafbfb156a0e0a5ab17fb5b9b1df0bb64e78df9dd99a6feb27660ec94ec90faa2ae52494650f0b693b8cc }

condition:
	$a0
}

        