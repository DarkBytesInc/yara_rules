rule Win_Trojan_Pakes_756
{
strings:
	$a0 = { bd8ccb0ef15585c2360678ee3802aa773d29b87dd994f5253da1b5f6d29e6bac54d0abf394006461e8956af9b896c3e4416175d9b3696ce74874e1ee273b6d991c9cb6d338a16676099c9d25674a7cd416717165422b75dffd80aa4be4fff91cc59b5efd67662c2a48d489fce30cd67dbd63d99c9f17c353942462b6e99d62d1977bd586aea1bef9af1c01ed }

condition:
	$a0
}

        