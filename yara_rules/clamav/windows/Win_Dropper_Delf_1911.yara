rule Win_Dropper_Delf_1911
{
strings:
	$a0 = { 8b3a7f5414d7b9b33bb330c220ab2c8a0a01e39a484003ae26d10daf2b20d95a6317101444a32da65be26b28cc447282ca66e4d5ebcd369cbe9c9e9e979ed7704cceb1eff4bd43fafa5e8849f31616f961d4e08f2afe486b7eb5e8c49628d11529f3beefceec8aa99af0c77e77eefdee77bfdfdf776708073d9c3efffc }

condition:
	$a0
}

        
