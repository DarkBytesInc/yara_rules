rule Win_Trojan_SdBot_4493
{
strings:
	$a0 = { af926a01463afc336f42276d85d21168440f676a083233267e4fde623941259e78ca6a0e647acca721165b8685f63141e89d90405de85b0156740a906bba0ca3c63df5a10135dc21104766cea87d0df3c4c45dfb7fc5b0a27e360c201d11e62a8b4e04789a00eb180a8b0e0141890eeb07b31d2428984b59169a505c033c0621aaa775d9006602d15f5b5dc33bbc8bb8577df1747a20 }

condition:
	$a0
}

        