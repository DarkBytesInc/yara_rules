rule Win_Dropper_Delf_1686
{
strings:
	$a0 = { 3bf3a8fcd487acaeacd6acd4189decacd4acacac2c54bd5cadad336c239875f3a4acafacac3bf3a4fc3b335caaadadfc3bf3a0fcd6acd6ac39f3a8fc545c5dadad39f3a8fc54455dadad3b335caaadadfc54d95cadad397c3bf35c549f54adad39f35c2ce48e23933bf35cfc39c35c647c9decac545456adad3974316fae66aeacacac39f35c54fa56adad59913bf35cfc39c35c647c }

condition:
	$a0
}

        