package bridge

// Transport абстрактный интерфейс для любого типа подключения к Telegram DC
// Реализуется как WebSocket, так и прямым TCP
type Transport interface {
	// Send отправляет бинарные данные
	Send(data []byte) error
	// Recv получает следующие бинарные данные
	Recv() ([]byte, error)
	// Close закрывает соединение
	Close() error
	// IsClosed возвращает true если соединение закрыто
	IsClosed() bool
}
