rule Win_Spyware_Banker_5930
{
strings:
	$a0 = { de86721f0d6fbea5089dc198998a76f24ef7ee9df0a296f0019e54c303d04e134d860187ca7a6d328e12777dbcb5c60ae5d8446efe8b49cf18abbbc99922de70e45b569a47cb377a3742921b7a7f3f63ead189302e2fa7c0b71b271abc2c6b5ab5410cd32cdb5ff04f4f6788e5f99a35d27d8b8f29a162364cfcf5cc2415e37a01cc86750ac179c0d0ec042f }

condition:
	$a0
}

        