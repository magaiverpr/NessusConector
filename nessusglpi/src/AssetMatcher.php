<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

class AssetMatcher
{
    public function findMatch(array $host, array $allowedItemtypes): ?array
    {
        foreach ($allowedItemtypes as $itemtype) {
            $match = $this->findByName($host['hostname'] ?? '', $itemtype);
            if ($match !== null) {
                return $match;
            }

            $match = $this->findByName($host['fqdn'] ?? '', $itemtype);
            if ($match !== null) {
                return $match;
            }
        }

        return null;
    }

    private function findByName(string $name, string $itemtype): ?array
    {
        global $DB;

        if ($name === '' || !class_exists($itemtype)) {
            return null;
        }

        $item = getItemForItemtype($itemtype);
        if (!$item instanceof \CommonDBTM) {
            return null;
        }

        $table = $item->getTable();
        $row   = $DB->request([
            'FROM'  => $table,
            'WHERE' => ['name' => $name],
            'LIMIT' => 1,
        ])->current();

        if (!$row) {
            return null;
        }

        return [
            'itemtype' => $itemtype,
            'items_id' => (int) $row['id'],
            'name'     => $row['name'],
        ];
    }
}
