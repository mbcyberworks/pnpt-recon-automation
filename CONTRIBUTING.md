# Contributing to PNPT Reconnaissance Automation

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🤝 Ways to Contribute

### Report Bugs
- Use GitHub Issues
- Include system details (OS, tool versions)
- Provide reproduction steps
- Include relevant logs

### Suggest Features
- Open a GitHub Issue with [Feature Request] tag
- Describe the use case
- Explain expected behavior
- Consider implementation complexity

### Submit Code
- Fork the repository
- Create a feature branch
- Write clear commit messages
- Test thoroughly
- Submit a Pull Request

### Improve Documentation
- Fix typos and errors
- Add examples
- Clarify instructions
- Update outdated information

## 📋 Development Guidelines

### Code Style
- Follow existing bash script conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small
- Use proper error handling

### Testing
Before submitting:
```bash
# Test basic functionality
./pnpt-recon-pipeline.sh -d yourdomain.com --quick

# Test all scan modes on your own infrastructure
./pnpt-recon-pipeline.sh -d yourdomain.com --quick
./pnpt-recon-pipeline.sh -d yourdomain.com
./pnpt-recon-pipeline.sh -d yourdomain.com --thorough

# Verify output structure
ls -la recon_*/

# Check for errors in logs
grep -i error recon_*/logs/*.log
```

### Commit Messages
Format:
```
[Type] Short description

Detailed explanation if needed

- Bullet points for multiple changes
- Reference issues with #123
```

Types:
- `[Feature]` - New functionality
- `[Fix]` - Bug fixes
- `[Docs]` - Documentation updates
- `[Refactor]` - Code improvements
- `[Test]` - Testing additions
- `[Chore]` - Maintenance tasks

### Pull Request Process

1. **Fork & Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean code
   - Add comments
   - Update documentation

3. **Test Thoroughly**
   - Test on multiple targets
   - Verify all scan modes
   - Check error handling

4. **Update Documentation**
   - Update README.md if needed
   - Add to CHANGELOG.md
   - Document new features

5. **Submit PR**
   - Clear description
   - Reference related issues
   - Explain changes made

6. **Review Process**
   - Address review comments
   - Make requested changes
   - Keep discussion professional

## 🎯 Priority Areas

### High Priority
- Bug fixes affecting functionality
- Performance improvements
- Security enhancements
- Critical documentation updates

### Medium Priority
- New tool integrations
- Additional scan modes
- Output format improvements
- Enhanced error messages

### Future Enhancements
- HTML report generation
- Intelligent finding analysis
- Screenshot capture
- Risk scoring system
- Integration with other frameworks

## 🐛 Bug Reports

Good bug reports include:

**System Information**
```
OS: Kali Linux 2024.2
Bash: 5.2.15
Go: 1.21.5
Tool versions: (run with --version)
```

**Reproduction Steps**
```
1. Run command: ./pnpt-recon-pipeline.sh -d target.com
2. Phase 3 fails with error: ...
3. Check logs show: ...
```

**Expected vs Actual**
- Expected: Port scan completes successfully
- Actual: Script exits with error code 1

**Logs**
```
Attach relevant log files from recon_*/logs/
```

## 💡 Feature Requests

Good feature requests include:

**Use Case**
Describe the problem or need

**Proposed Solution**
How would you solve it?

**Alternatives Considered**
What other approaches did you think about?

**Additional Context**
Screenshots, examples, references

## 📝 Documentation

When updating documentation:

- Use clear, concise language
- Include code examples
- Add screenshots when helpful
- Keep formatting consistent
- Test all commands/examples
- Update table of contents

## ⚠️ Code of Conduct

### Our Standards

✅ **Do:**
- Be respectful and professional
- Provide constructive feedback
- Help others learn
- Focus on code, not people
- Accept feedback gracefully

❌ **Don't:**
- Use offensive language
- Make personal attacks
- Harass or discriminate
- Share private information
- Spam or troll

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban
3. Permanent ban

Report issues to: [maintainer contact]

## 🔒 Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email details privately
2. Include reproduction steps
3. Suggest fixes if possible
4. Allow time for patch

### Responsible Disclosure

- Give maintainers reasonable time to fix
- Don't exploit in the wild
- Coordinate public disclosure
- Credit will be given

## 📧 Contact

- **GitHub Issues**: For bugs and features
- **Pull Requests**: For code contributions
- **Email**: For security issues
- **Website**: [mbcyberworks.nl](https://mbcyberworks.nl)

## 🙏 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation
- Appreciated by the community!

---

**Thank you for contributing to PNPT Reconnaissance Automation!**

Your efforts help the entire cybersecurity community.
