rule Win_Spyware_Banker_2527
{
strings:
	$a0 = { 8e814362266e9152d4285690dd59affbc62ae6eee98e9d472abfb875f69d0c508d1ad19c5ec01c15936e042c8eccf2152f8972a6267d517fb8468c82e96be17a281b1858b629c036c16889365146e8d7ffc423139ad9a74abaec3b409734da51e216b048a7f89f119aaa9e3cb6d41d14292deb34be516909ac0c23167345d14f4616bd710cf8cee6b0d1bf9e }

condition:
	$a0
}

        