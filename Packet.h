#pragma once
class Packet
{
private:
    void allocatePacketBuffer(); //sizeof header + ... + ...
public:
    virtual void deliver();
    Packet(/* args */);
    ~Packet();
};

Packet::Packet(/* args */)
{
}

Packet::~Packet()
{
}
