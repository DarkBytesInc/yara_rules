rule Win_Trojan_B_255
{
strings:
	$a0 = { fa33c08ed0bc007c8bf48ed88ec0fbfcbf0006b90001f3a5ea2106000005d46585bb0080b90a00ba8000b80802cd138816047c8bfb8bf3b93c0b33db891e007cc706027c000833d24a33c0acd1c803d033c303d886f3e2f3b801003b953c0b751c3b9d3e0b7516803de97511817d01e201750a2e8a16047c2eff2e007c33c08ec08ed8bebe07b304803c80740e803c00751c83c610fecb75efcd188b148b4c028bee83c610fecb740d803c0074f4bef306e83900ebfebf0500bb007cb8010257cd135f730c33c0cd134f75edbe0b07ebe0be2a07bffe7d813d55aa75d48bf5ea007c000056bb0700b40ecd105eac84c075f2c3 }

condition:
	$a0
}

        