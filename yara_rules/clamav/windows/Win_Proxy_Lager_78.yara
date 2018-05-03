rule Win_Proxy_Lager_78
{
strings:
	$a0 = { 7fb4329b6858871bb18c5f60c6a330c0712c7943ef2070a7c93285446db0b7e1b35bbad8d99ec31412dd1cda2954bc4ef063ee778860890d452bd974c78eeac2fa55f56dcb37 }

condition:
	$a0
}

        
