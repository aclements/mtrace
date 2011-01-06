#include <stack>

using namespace::std;

struct CallInterval {
	uint64_t id_;
	uint64_t call_trace_tag_;
	int	 cpu_;
	
	uint64_t start_pc_;
	uint64_t end_pc_;

	uint64_t access_start_;
	uint64_t access_end_;

	uint64_t prev_;
	uint64_t next_;
	uint64_t ret_;
};

struct CallTrace {
	CallTrace(struct mtrace_fcall_entry *f) {
		start_ = f;
		current_ = NULL;
	}

	void push(struct mtrace_call_entry *f) {
		end_current(f->h.access_count, f->return_pc);
		
		current_ = new_call_interval(f);

		if (!stack_.empty())
			current_->ret_ = stack_.top()->id_;

		stack_.push(current_);
	}

	void pop(struct mtrace_call_entry *f) {
		end_current(f->h.access_count, f->target_pc);

		/* Pop top frame */
		if (!stack_.empty())
			stack_.pop();

		current_ = new_call_interval(f);

		/* Replace top frame with current */
		if (!stack_.empty())
			stack_.pop();
		if (!stack_.empty()) {
			current_->ret_ = stack_.top()->id_;
		}
		stack_.push(current_);
	}

	static CallInterval *new_call_interval(struct mtrace_call_entry *ce) {
		CallInterval *ci;

		ci = new CallInterval();
		ci->access_start_ = ce->h.access_count;
		ci->id_ = ++call_interval_count;
		ci->cpu_ = ce->h.cpu;
		ci->start_pc_ = ce->target_pc;

		return ci;
	}

	static void free_call_interval(CallInterval *ci) {
		delete ci;
	}

	void free_timeline(void) {
		while (!timeline_.empty()) {
			CallInterval *ci = timeline_.front();
			timeline_.pop_front();
			free_call_interval(ci);
		}
	}

	void end_current(uint64_t end_count, uint64_t end_pc) {
		if (current_ != NULL) {
			if (!timeline_.empty()) {
				CallInterval *prev;
				prev = timeline_.back();

				prev->next_ = current_->id_;
				current_->prev_ = prev->id_;
			}

			current_->access_end_ = end_count;
			current_->end_pc_ = end_pc;
			timeline_.push_back(current_);
			current_ = NULL;
		}
	}

	CallInterval			*current_;
	struct mtrace_fcall_entry 	*start_;
	list<CallInterval *> 		timeline_;
	stack<CallInterval *>		stack_;

	static uint64_t   		call_interval_count;
};
