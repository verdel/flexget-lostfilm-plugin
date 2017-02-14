Flexget input plugin for Lostfilm.tv
=====================================

This contains flexget input plugin for https://www.lostfilm.tv. After the site has been updated to the new version from RSS disappeared direct links to the torrent files. This plugin get item from RSS and after that get direct links to the torrent files from item series page.

Install
-------

This will work after flexget-lostfilm-plugin is released::

    pip install https://github.com/verdel/flexget-lostfilm-plugin/archive/master.zip

Usage
-----

Parses Lostfilm RSS feed and get direct link to torrent files from series page on site.

#### Configuration for lostfilm:

    lostfilm:
        email: <email>
        password: <password>

#### Advanced usages:
You can disable few possibly annoying warnings by setting silent value to yes on feeds where there are frequently invalid items.

**Example:**
        
    lostfilm:
        email: <email>
        password: <password>
        silent: yes

