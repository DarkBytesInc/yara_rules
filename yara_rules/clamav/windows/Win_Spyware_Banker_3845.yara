rule Win_Spyware_Banker_3845
{
strings:
	$a0 = { 052408d4145191fca91028402273f720708376ad36ee7731bb9dee69fc3bfc077b99dc816f77205b776035dc815abc8aeac17b5bc905d2023ae405b720375c906d72457ae4856dce09ab920fa6406eb920eddc06f7bb905dddc836ddc15bb98eee66effffffedf7fdf3e7dfbce79e7df3f7df3cf3f739fdbe7bfc08a971c45217ad56ab4592c5691e3be9ffe }

condition:
	$a0
}

        