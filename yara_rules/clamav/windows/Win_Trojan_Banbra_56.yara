rule Win_Trojan_Banbra_56
{
strings:
	$a0 = { 53812710014615545055133f22282d254b4901c00a03387a5a564a5d3362474156bf8011568303292e6a40465411c5e0c3df8c5be8c4e084161e46797d79615e5800067a0f0c8bf5780c9230405bf9b49f9e9d85f21880619b662c9b67c8125fe2a79dc184012053d686bfbdaace38ac2c01345bb6feddcb85b5e5b082 }

condition:
	$a0
}

        