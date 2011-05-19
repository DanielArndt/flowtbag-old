#!/usr/bin/python

'''
   Copyright 2011 Daniel Arndt

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Contributors:

   @author: Daniel Arndt <danielarndt@gmail.com>
'''

class FlowFeature:
    def __init__(self, name, desc="", bi_dir=False):
        self.name = name # Name of the feature
        self.desc = desc # Description of the feature
        self.bi_dir = bi_dir # Is the flow bi-directional?

    def add_to_value(self, amt, reverse=False):
        if reverse:
            self.rvalue += amt

    def __repr__(self):
        # TODO: Write this
        return ""

    def __str__(self):
        # TODO: Write this
        return ""
