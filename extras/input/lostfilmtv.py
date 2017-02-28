#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import unicode_literals, division, absolute_import
from builtins import *  # noqa pylint: disable=unused-import, redefined-builtin
from future.utils import tobytes
from past.builtins import basestring
from future.moves.urllib.parse import urlparse

import os
import logging
import re
import xml.sax
import http.client
from datetime import datetime

import dateutil.parser

import feedparser
from requests import RequestException

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event
from flexget.utils.cached_input import cached
from flexget.utils.pathscrub import pathscrub
from flexget.utils.soup import get_soup

log = logging.getLogger('losfilmtv')
feedparser.registerDateHandler(lambda date_string: dateutil.parser.parse(date_string).timetuple())


class LostfilmRSS(object):
    """
    Parses Lostfilm RSS feed and get direct link to torrent files from series page on site.

    Configuration for lostfilm:

      losfilmtv:
        email: <email>
        password: <password>

    Advanced usages:

    You can disable few possibly annoying warnings by setting silent value to
    yes on feeds where there are frequently invalid items.

    Example::

      losfilmtv:
        email: <email>
        password: <password>
        silent: yes

    """

    schema = {
        'properties': {
            'email': {'type': 'string'},
            'password': {'type': 'string'},
            'silent': {'type': 'boolean', 'default': False},
            'filename': {'type': 'boolean'},
            'all_entries': {'type': 'boolean', 'default': True},
        },
        'required': ['email', 'password'],
        'additionalProperties': False
    }

    def _build_config(self, task, config):
        config.setdefault('title', 'title')
        config.setdefault('all_entries', True)
        config['rss-url'] = 'https://www.lostfilm.tv/rss.xml'
        config['series-search-url'] = 'https://lostfilm.tv/v_search.php'
        config['auth-url'] = 'https://www.lostfilm.tv/ajaxik.php'
        return config

    def _get_session_token(self, task, config):
        try:
            payload = {'act': 'users', 'type': 'login', 'mail': config['email'], 'pass': config['password'], 'rem': '0'}
            response = task.requests.post(config['auth-url'], timeout=60, data=payload, raise_status=False)
            content = response.json()
        except RequestException as e:
            raise plugin.PluginError('Unable to get session token for task %s (%s) credentials(): %s' %
                                     (task.name, config['auth-url'], e))

        if 'success' not in content and 'error' in content:
            raise plugin.PluginError('Unable to get session token for task %s (%s): %s' %
                                     (task.name, config['auth-url'], response.content))

    def _get_url_from_site(self, task, config, entry):
        entries = list()
        try:
            response = task.requests.get(entry['url'], timeout=60, raise_status=False)
            data = response.content
        except RequestException as e:
            raise plugin.PluginError('Unable to download the data for task %s (%s): %s' %
                                     (task.name, entry['url'], e))
        soup = get_soup(data, 'html.parser')

        copyrightedEpisode = soup.find('div', {'onclick': 'copyrightedEpisode()'})
        if copyrightedEpisode:
            log.warning('Copyrighted episode. Unable to download data for task: %s, title: %s (%s)' %
                        (task.name, entry['title'], entry['url']))
            return entries

        episode_attr = soup.find('div', {'onclick': re.compile(r"PlayEpisode\('[\d]*','[\d]*','[\d]*'\)")})
        if episode_attr:
            episode_attr = episode_attr.attrs['onclick']

        match = re.search("PlayEpisode\('([\d]*)','([\d]*)','([\d]*)'\)", episode_attr)
        show_id = int(match.group(1))
        season_id = int(match.group(2))
        episode_id = int(match.group(3))
        try:
            response = task.requests.get('{}?c={}&s={}&e={}'.format(config['series-search-url'], show_id, season_id, episode_id), timeout=60)
            data = response.content
        except RequestException as e:
            raise plugin.PluginError('Unable to download the data for task %s (%s): %s' %
                                     (task.name, '{}?c={}&s={}&e={}'.format(show_id, season_id, episode_id), e))

        soup = get_soup(data, 'html.parser')
        retre_url = soup.a['href']

        try:
            response = task.requests.get(retre_url, timeout=60, raise_status=False)
            data = response.content
        except RequestException as e:
            raise plugin.PluginError('Unable to download the data for task %s (%s): %s' %
                                     (task.name, retre_url, show_id, season_id, episode_id), e)

        retre_data = get_soup(data, 'html.parser')
        for item in retre_data.find_all('div', {'class': 'inner-box--item'}):
            info = item.find('div', {'class': 'inner-box--link main'})
            item_url = info.a['href']
            item_text = info.a.string.replace('\n', '').replace('\r', '')

            re_pattern = re.compile(ur"^.*\.(.*)$", re.UNICODE)
            result = re_pattern.search(item_text)
            quality = result.group(1)

            title = re.match('^(.*)\s\((.*)\)\.\s(.*)\.\s\((.*)\)$', entry['title'])

            item_entry = Entry()
            item_entry['title'] = '{} ({}).{}.{}'.format(title.group(1), title.group(2), title.group(4), quality)
            item_entry['url'] = item_url

            if entry.get('rss_pubdate'):
                item_entry['rss_pupdate'] = entry['rss_pubdate']

            entries.append(item_entry)
        return entries

    def _process_invalid_content(self, task, data, url):
        """If feedparser reports error, save the received data and log error."""

        if data is None:
            log.critical('Received empty page - no content')
            return
        else:
            data = tobytes(data)

        ext = 'xml'
        if b'<html>' in data.lower():
            log.critical('Received content is HTML page, not an RSS feed')
            ext = 'html'
        if b'login' in data.lower() or b'username' in data.lower():
            log.critical('Received content looks a bit like login page')
        if b'error' in data.lower():
            log.critical('Received content looks a bit like error page')
        received = os.path.join(task.manager.config_base, 'received')
        if not os.path.isdir(received):
            os.mkdir(received)
        filename = task.name
        sourcename = urlparse(url).netloc
        if sourcename:
            filename += '-' + sourcename
        filename = pathscrub(filename, filename=True)
        filepath = os.path.join(received, '%s.%s' % (filename, ext))
        with open(filepath, 'wb') as f:
            f.write(data)
        log.critical('I have saved the invalid content to %s for you to view', filepath)

    @cached('lostfilm')
    @plugin.internet(log)
    def on_task_input(self, task, config):
        config = self._build_config(task, config)
        self._get_session_token(task, config)

        log.debug('Requesting task `%s` url `%s`', task.name, config['rss-url'])

        # Used to identify which etag/modified to use
        url_hash = str(hash(config['rss-url']))

        # set etag and last modified headers if config has not changed since
        # last run and if caching wasn't disabled with --no-cache argument.
        all_entries = (config['all_entries'] or task.config_modified or
                       task.options.nocache or task.options.retry)
        headers = {}
        if not all_entries:
            etag = task.simple_persistence.get('%s_etag' % url_hash, None)
            if etag:
                log.debug('Sending etag %s for task %s', etag, task.name)
                headers['If-None-Match'] = etag
            modified = task.simple_persistence.get('%s_modified' % url_hash, None)
            if modified:
                if not isinstance(modified, basestring):
                    log.debug('Invalid date was stored for last modified time.')
                else:
                    headers['If-Modified-Since'] = modified
                    log.debug('Sending last-modified %s for task %s', headers['If-Modified-Since'], task.name)

        # Get the feed content
        if config['rss-url'].startswith(('http', 'https')):
            # Get feed using requests library
            try:
                # Use the raw response so feedparser can read the headers and status values
                response = task.requests.get(config['rss-url'], timeout=60, headers=headers, raise_status=False)
                content = response.content
            except RequestException as e:
                raise plugin.PluginError('Unable to download the RSS for task %s (%s): %s' %
                                         (task.name, config['rss-url'], e))

            # status checks
            status = response.status_code
            if status == 304:
                log.verbose('%s hasn\'t changed since last run. Not creating entries.', config['rss-url'])
                # Let details plugin know that it is ok if this feed doesn't produce any entries
                task.no_entries_ok = True
                return []
            elif status == 401:
                raise plugin.PluginError('Authentication needed for task %s (%s): %s' %
                                         (task.name, config['rss-url'], response.headers['www-authenticate']), log)
            elif status == 404:
                raise plugin.PluginError('RSS Feed %s (%s) not found' % (task.name, config['rss-url']), log)
            elif status == 500:
                raise plugin.PluginError('Internal server exception on task %s (%s)' % (task.name, config['rss-url']), log)
            elif status != 200:
                raise plugin.PluginError('HTTP error %s received from %s' % (status, config['rss-url']), log)

            # update etag and last modified
            if not config['all_entries']:
                etag = response.headers.get('etag')
                if etag:
                    task.simple_persistence['%s_etag' % url_hash] = etag
                    log.debug('etag %s saved for task %s', etag, task.name)
                if response.headers.get('last-modified'):
                    modified = response.headers['last-modified']
                    task.simple_persistence['%s_modified' % url_hash] = modified
                    log.debug('last modified %s saved for task %s', modified, task.name)

        if not content:
            log.error('No data recieved for rss feed.')
            return []
        try:
            rss = feedparser.parse(content)
        except LookupError as e:
            raise plugin.PluginError('Unable to parse the RSS (from %s): %s' % (config['rss-url'], e))

        # check for bozo
        ex = rss.get('bozo_exception', False)
        if ex or rss.get('bozo'):
            if rss.entries:
                msg = 'Bozo error %s while parsing feed, but entries were produced, ignoring the error.' % type(ex)
                if config.get('silent', False):
                    log.debug(msg)
                else:
                    log.verbose(msg)
            else:
                if isinstance(ex, feedparser.NonXMLContentType):
                    # see: http://www.feedparser.org/docs/character-encoding.html#advanced.encoding.nonxml
                    log.debug('ignoring feedparser.NonXMLContentType')
                elif isinstance(ex, feedparser.CharacterEncodingOverride):
                    # see: ticket 88
                    log.debug('ignoring feedparser.CharacterEncodingOverride')
                elif isinstance(ex, UnicodeEncodeError):
                    raise plugin.PluginError('Feed has UnicodeEncodeError while parsing...')
                elif isinstance(ex, (xml.sax._exceptions.SAXParseException, xml.sax._exceptions.SAXException)):
                    # save invalid data for review, this is a bit ugly but users seem to really confused when
                    # html pages (login pages) are received
                    self._process_invalid_content(task, content, config['rss-url'])
                    if task.options.debug:
                        log.error('bozo error parsing rss: %s' % ex)
                    raise plugin.PluginError('Received invalid RSS content from task %s (%s)' % (task.name,
                                                                                                 config['rss-url']))
                elif isinstance(ex, http.client.BadStatusLine) or isinstance(ex, IOError):
                    raise ex  # let the @internet decorator handle
                else:
                    # all other bozo errors
                    self._process_invalid_content(task, content, config['rss-url'])
                    raise plugin.PluginError('Unhandled bozo_exception. Type: %s (task: %s)' %
                                             (ex.__class__.__name__, task.name), log)

        log.debug('encoding %s', rss.encoding)

        last_entry_id = ''
        if not all_entries:
            # Test to make sure entries are in descending order
            if rss.entries and rss.entries[0].get('published_parsed') and rss.entries[-1].get('published_parsed'):
                if rss.entries[0]['published_parsed'] < rss.entries[-1]['published_parsed']:
                    # Sort them if they are not
                    rss.entries.sort(key=lambda x: x['published_parsed'], reverse=True)
            last_entry_id = task.simple_persistence.get('%s_last_entry' % url_hash)

        # new entries to be created
        entries = list()

        ignored = 0
        for entry in rss.entries:
            # Check if title field is overridden in config
            title_field = 'title'
            # ignore entries without title
            if not entry.get(title_field):
                log.debug('skipping entry without title')
                ignored += 1
                continue

            # Set the title from the source field
            entry.title = entry[title_field]

            # Check we haven't already processed this entry in a previous run
            if last_entry_id == entry.title + entry.get('guid', ''):
                log.verbose('Not processing entries from last run.')
                # Let details plugin know that it is ok if this task doesn't produce any entries
                task.no_entries_ok = True
                break

            # remove annoying zero width spaces
            entry.title = entry.title.replace(u'\u200B', u'')

            # create flexget entry
            entry_info = {}
            entry_info['title'] = entry['title']
            entry_info['url'] = entry['link']
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                entry_info['rss_pubdate'] = datetime(*entry.published_parsed[:6])

            if not entry_info.get('url'):
                log.debug('%s does not have link (%s) or enclosure', entry['title'])
                ignored += 1
                continue

            for item in self._get_url_from_site(task, config, entry_info):
                    entries.append(item)

        # Save last spot in rss
        if rss.entries:
            log.debug('Saving location in rss feed.')
            try:
                task.simple_persistence['%s_last_entry' % url_hash] = (rss.entries[0].title +
                                                                       rss.entries[0].get('guid', ''))
            except AttributeError:
                log.debug('rss feed location saving skipped: no title information in first entry')

        if ignored:
            if not config.get('silent'):
                log.warning('Skipped %s RSS-entries without required information (title, link or enclosures)', ignored)

        return entries


@event('plugin.register')
def register_plugin():
    plugin.register(LostfilmRSS, 'losfilmtv', api_ver=2)
