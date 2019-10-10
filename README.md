# Illumio Coding Assignment

The tricky part of the given problem is to handle the trade off between the time and space complexity of the algorithm to solve it. To make the lookup faster I decided to go with nested TreeMap since the lookup is O(1).


Improvements that I  would have liked to add to my code would be 
1) Using trie for look up
2) Saved the range of IPs as such instead of parsing and finding all the IP's between the given range
3) enum to hold protocol and direction values

If I was given more time I would have modified the code to implement the above mentioned changes. In worst case scenario the space required would be in TB's where all the IPV4 needs to be saved and kept in memory for rule check. so I would have saved the range as such and adjusted the range in trie based on new rule if there is an overlap.


Team Preference

Platform Team
Policy Team
