rule Win_Trojan_Servu_40
{
strings:
	$a0 = { 6caba14ad8d0e563ca76d8f61dcb38b28e81037dfc493d8116114afe2ff2e9fc3b9dc1ce65cc846dcc846e5eec079cb2036f24895b2035bb20a904adb9006b900adc8029901b6e6c053046ae48026420a66c0432015320153056a600a995ef3bdee76f3fffffd7efcf9f3efdf9f7cfbe79e7bef9ef99bfd77e7efe009af3bdd240830d9cdfc37451580cab3d }

condition:
	$a0
}

        