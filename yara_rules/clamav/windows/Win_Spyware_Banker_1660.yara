rule Win_Spyware_Banker_1660
{
strings:
	$a0 = { ab4d5877c6bf5d07443854a39d946bb8a8485f84ea79304384dc6a76cdaca7048dc0d632ecfbb1f35a79979367bc1f43b83ba0e7968ce622a6bde9240ba37aeac394690b9d8972e6d85948de01629c83bc3762e63f6aa8bb59c875fb4b787a9e60882b1c678e18537ae748b9b8e34d1db4622fa883dfbb69d824e3be1140bec9818b3a03a6d2ebb9bc56aca7cbcac5e0409b76 }

condition:
	$a0
}

        