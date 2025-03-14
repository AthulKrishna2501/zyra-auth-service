package events

import (
	"log"

	"github.com/rabbitmq/amqp091-go"
)

type RabbitMq struct {
	Conn    *amqp091.Connection
	Channel *amqp091.Channel
}

func NewRabbitMq(url string) (*RabbitMq, error) {
	conn, err := amqp091.Dial(url)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()

	if err != nil {
		return nil, err
	}

	_, err = ch.QueueDeclare(
		"otp_queue",
		true,
		false,
		false,
		false,
		nil,
	)

	if err != nil {
		return nil, err
	}

	return &RabbitMq{Conn: conn, Channel: ch}, nil
}

func (r *RabbitMq) PublishOTP(email, otp string) error {
	body := `{"email": "` + email + `", "otp": "` + otp + `"}`
	err := r.Channel.Publish(
		"",
		"otp_queue",
		false,
		false,
		amqp091.Publishing{
			ContentType: "application/json",
			Body:        []byte(body),
		},
	)

	if err != nil {
		return err
	}

	log.Println("Published OTP event: ", body)
	return nil
}
func (r *RabbitMq) Close() {
	r.Channel.Close()
	r.Conn.Close()
}
