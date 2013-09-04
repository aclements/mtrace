#pragma once

#include <functional>

class generator_stop
{
};

template<typename T>
class generator
{
    std::function<T()> f_;

public:
    typedef T value_type;
    typedef T& reference;
    typedef const T& const_reference;

    generator(std::function<T()> &&function)
        : f_(std::move(function)) { }

    class iterator
    {
        std::function<T()> f_;
        T val_;

    public:
        iterator(const std::function<T()> &function)
            : f_(function), val_()
        {
            ++(*this);
        }

        iterator() = default;

        bool operator!=(const iterator &o) const
        {
            return f_ || o.f_;
        }

        const_reference operator*() const
        {
            return val_;
        }

        iterator& operator++()
        {
            if (f_) {
                try {
                    val_ = f_();
                } catch (generator_stop &e) {
                    f_ = nullptr;
                }
            }
            return *this;
        }
    };

    iterator begin()
    {
        return iterator(f_);
    }

    iterator end()
    {
        return iterator();
    }
};

// Return a generator whose iterator will produce the values returned
// by repeated evaluations of function().  function() must throw
// generator_stop when it can yield no more values.
//
// For example, to generate the numbers 0 through 9:
//   int i = 0;
//   generator<int> gen = make_generator([=]() mutable {
//     if (i < 10) return i++;
//     throw generator_stop();
//   });
//   for (int result : gen)
//     cout << result << endl;
template<typename F>
auto make_generator(F &&function) -> generator<decltype(function())>
{
    return generator<decltype(function())>(std::move(function));
}
