<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\TicketService;

include('../../../inc/includes.php');

Session::checkRight(Host::$rightname, UPDATE);
Html::header_nocache();

$id      = (int) ($_POST['id'] ?? 0);
$service = new TicketService();

try {
    $ticketId = $service->createTicketFromHost($id);
    echo json_encode([
        'ok'         => true,
        'tickets_id' => $ticketId,
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'ok'      => false,
        'message' => $e->getMessage(),
    ], JSON_THROW_ON_ERROR);
}
