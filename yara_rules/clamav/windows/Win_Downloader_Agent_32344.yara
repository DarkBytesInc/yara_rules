rule Win_Downloader_Agent_32344
{
strings:
	$a0 = { 7836d7675716b6f68536e2f585e2e8b24ab273dac9487b41463afa02b6076346e0f9350fc98d763ef75d32b2cd24a37676c121253cb9f3f2c40c74b7373c4b11301983e82697fc2028f11980c69636d6be01f0310e78836d96d2092c3646b6608666fb2369544baae2293f93e6646b08431f01263dbc235fc24e8783081c4e6b7009982e69ed470732ea7caf39025d55c8260857 }

condition:
	$a0
}

        