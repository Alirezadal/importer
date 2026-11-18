import unittest
from unittest.mock import patch
import base64
import main

class Sources(unittest.TestCase):
    def test_plain_and_base64(self):
        text = 'vless://abc@example.com:443#one\nss://abc@example.com:443#two'
        for payload in (text, base64.b64encode(text.encode()).decode(), base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')):
            self.assertEqual(main.parse_subscription(payload), text.splitlines())
    def test_invalid(self):
        with self.assertRaises(ValueError): main.parse_subscription('<html>error</html>')
    def test_ten_posts(self):
        html = ''.join(f'<div class="tgme_widget_message" data-post="SOSkeyNET/{i}"><div class="tgme_widget_message_text">vless://id@host:{i}</div></div>' for i in range(1,13))
        with patch('main.fetch', return_value=html):
            self.assertEqual(main.telegram('SOSkeyNET'), [f'vless://id@host:{i}' for i in range(3,13)])
    def test_merge(self):
        with patch('main.sources', side_effect=[['channel'], ['url','bad']]), patch('main.telegram', return_value=['a','b']), patch('main.subscription', side_effect=[['b','c'], ValueError()]):
            self.assertEqual(main.collect(), ['a','b','c'])
    def test_all_failed(self):
        with patch('main.sources', side_effect=[['channel'], []]), patch('main.telegram', side_effect=ValueError()):
            with self.assertRaises(RuntimeError): main.collect()

if __name__ == '__main__': unittest.main()
