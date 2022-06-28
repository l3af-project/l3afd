package kf

type platformInterface interface {
	GetPlatform() (string, error)
}
