<?php

declare(strict_types=1);

function ptt_xxe_extract_entity_url(string $xml): ?string
{
    if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
        return null;
    }

    $url = trim((string) ($matches[1] ?? ''));
    if ($url === '') {
        return null;
    }

    return $url;
}

function ptt_xxe_touch_sink(string $xml, string $sink): void
{
    try {
        if ($sink === 'dom' || $sink === 'dom_loadxml') {
            $document = new DOMDocument();
            @$document->loadXML($xml);
            return;
        }

        if ($sink === 'dom_load') {
            $document = new DOMDocument();
            @$document->load($xml);
            return;
        }

        if ($sink === 'xmlreader' || $sink === 'xmlreader_xml') {
            $reader = new XMLReader();
            @$reader->XML($xml);
            @$reader->close();
            return;
        }

        if ($sink === 'xmlreader_open') {
            $reader = new XMLReader();
            @$reader->open($xml);
            @$reader->close();
            return;
        }

        if ($sink === 'simplexml_file' || $sink === 'simplexml_load_file') {
            @simplexml_load_file($xml);
            return;
        }

        if ($sink === 'simplexml' || $sink === 'simplexml_load_string') {
            @simplexml_load_string($xml);
            return;
        }

        @simplexml_load_string($xml);
    } catch (Throwable) {
        // Intentionally swallow parser errors in this vulnerable fixture.
    }
}

function ptt_xxe_safe_render(string $xml): string
{
    $parsed = @simplexml_load_string($xml);
    if ($parsed === false) {
        return 'xml parse failed';
    }

    return trim((string) $parsed);
}

$xml = (string) ($_GET['xml'] ?? '<root>safe</root>');
$mode = (string) ($_GET['mode'] ?? 'vuln');
$sink = strtolower((string) ($_GET['sink'] ?? 'simplexml'));

ptt_xxe_touch_sink($xml, $sink);

if ($mode === 'safe') {
    if (stripos($xml, '<!ENTITY') !== false || stripos($xml, '<!DOCTYPE') !== false) {
        http_response_code(403);
        echo 'entity blocked';
        return;
    }

    echo ptt_xxe_safe_render($xml);
    return;
}

$entityUrl = ptt_xxe_extract_entity_url($xml);
if ($entityUrl === null) {
    echo ptt_xxe_safe_render($xml);
    return;
}

$body = @file_get_contents($entityUrl);
if (!is_string($body) || $body === '') {
    http_response_code(502);
    echo 'xml fetch failed';
    return;
}

echo trim($body);
