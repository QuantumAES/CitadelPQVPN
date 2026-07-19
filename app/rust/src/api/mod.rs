pub mod citadel;
pub mod diag;
pub mod simple;
// Admin-режим (C7.4): управление реестром абонентов по туннелю (PQ-TLS admin-канал ядра).
// Единый бэкенд для всех платформ — включая мобильные (SSH/russh-путь удалён).
pub mod admin;
