rule Win_Proxy_Lager_38
{
strings:
	$a0 = { 27963763093d316677540d696f23ceb44b28b514b257d644ff12d06b10a15a129fcd23048a56e13401a480f1c380d17cc786d8f283183481e51d06aacc49fe44fc8ccd36b778 }

condition:
	$a0
}

        