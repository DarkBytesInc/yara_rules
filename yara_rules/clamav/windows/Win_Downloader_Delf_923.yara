rule Win_Downloader_Delf_923
{
strings:
	$a0 = { abc06baa7ecfdae792324a6d0ecd5b79fa86d355b56904cd1935cd1f0a99666c50b51bb228d4ec98f84afb2e6f1e8c0abce86ca3f79209a1c991b34260e20e6563941e9ed2a8c4a624be00212a624c204bb3885fb3da886a0cc82e991c2d20c7c0ed4d55 }

condition:
	$a0
}

        
